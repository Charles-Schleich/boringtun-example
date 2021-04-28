
use ron::de::from_reader;
use std::{fs::File, net::{Ipv4Addr, UdpSocket}};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use boringtun::noise::*;
use std::thread;


use serde::{Deserialize, Serialize, de::DeserializeOwned};
#[derive(Debug, Serialize, Deserialize)]
struct IP {
    ip: String
}

const MAX_PACKET: usize = 65536;
const IPV4_MIN_HEADER_SIZE: usize = 20;

fn connected_sock_pair() -> (UdpSocket, UdpSocket) {
    let addr_a = format!("localhost:{}", 30002);
    let addr_b = format!("localhost:{}", 30003);
    let sock_a = UdpSocket::bind(&addr_a).unwrap();
    let sock_b = UdpSocket::bind(&addr_b).unwrap();
    sock_a.connect(&addr_b).unwrap();
    sock_b.connect(&addr_a).unwrap();
    (sock_a, sock_b)
}

fn write_u16_be(val: u16, buf: &mut [u8]) {
    assert!(buf.len() >= 2);
    buf[0] = (val >> 8) as u8;
    buf[1] = val as u8;
}

// Compute the internet checksum of a buffer
fn ipv4_checksum(buf: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in 0..buf.len() / 2 {
        sum += u16::from_be_bytes([buf[i * 2], buf[i * 2 + 1]]) as u32;
    }
    if buf.len() % 2 == 1 {
        sum += (buf[buf.len() - 1] as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum >> 16) + sum & 0xffff;
    }
    !(sum as u16)
}


fn write_ipv4_ping(socket: &UdpSocket, data: &[u8], seq: u16, SRC_IP: Ipv4Addr, DEST_IP: Ipv4Addr) {
    let mut ipv4_header = [0u8; IPV4_MIN_HEADER_SIZE];
    let mut icmp_header = [0u8; 8];

    let packet_len = ipv4_header.len() + icmp_header.len() + data.len();

    ipv4_header[0] = (4 << 4) + 5; // version = 4, header length = 5 * 4
    write_u16_be(packet_len as u16, &mut ipv4_header[2..]); // packet length
    ipv4_header[8] = 64; // TTL
    ipv4_header[9] = 1; // ICMP

    ipv4_header[12..16].copy_from_slice(&SRC_IP.octets());
    ipv4_header[16..20].copy_from_slice(&DEST_IP.octets());

    let checksum = ipv4_checksum(&ipv4_header);
    write_u16_be(checksum, &mut ipv4_header[10..]);

    icmp_header[0] = 8; // PING
    write_u16_be(654, &mut icmp_header[4..]); // identifier
    write_u16_be(seq, &mut icmp_header[6..]); // sequence number

    let mut packet = Vec::new();
    packet.extend_from_slice(&ipv4_header);
    packet.extend_from_slice(&icmp_header);
    packet.extend_from_slice(&data);

    // Compute the checksum of the icmp header + payload
    let icmp_checksum = ipv4_checksum(&packet[20..]);
    write_u16_be(icmp_checksum, &mut packet[20 + 2..]);

    println!("iface_socket_return send {:?} {:?} ",socket.local_addr(), packet);
    socket.send(&packet).unwrap();
}



// Validate a ping reply packet
fn read_ipv4_ping(socket: &UdpSocket, want_seq: u16) -> Vec<u8> {
    let mut data = [0u8; MAX_PACKET];
    let mut packet = Vec::new();
    if let Ok(len) = socket.recv(&mut data) {
        assert!(len >= IPV4_MIN_HEADER_SIZE);
        assert_eq!(data[0] >> 4, 4);

        let hdr_len = ((data[0] & 15) * 4) as usize;
        assert!(len >= hdr_len + 8);
        let ipv4_header = &data[..hdr_len];
        assert_eq!(ipv4_header[9], 1); // ICMP
        let icmp_header = &data[hdr_len..hdr_len + 8];
        let seq = u16::from_be_bytes([icmp_header[6], icmp_header[7]]);
        assert_eq!(seq, want_seq);

        packet.extend_from_slice(&data[hdr_len + 8..len]);
    } else {
        println!("skip {}", want_seq);
    }
    packet
}



// Start a WireGuard peer
fn wireguard_test_peer(
    network_socket: UdpSocket,
    static_private: &str,
    peer_static_public: &str,
    logger: Box<dyn Fn(&str) + Send>,
    close: Arc<AtomicBool>,
) -> UdpSocket {
    let static_private = static_private.parse().unwrap();
    let peer_static_public = peer_static_public.parse().unwrap();

    let mut peer = Tunn::new(
        Arc::new(static_private),
        Arc::new(peer_static_public),
        None,
        None,
        100,
        None,
    )
    .unwrap();
    peer.set_logger(logger, Verbosity::Trace);

    let peer: Arc<Box<Tunn>> = Arc::from(peer);

    let (iface_socket_ret, iface_socket) = connected_sock_pair();
    println!("iface_socket_ret {:?}",iface_socket_ret.local_addr());
    println!("iface_socket {:?}", iface_socket.local_addr());

    network_socket
        .set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();
    iface_socket
        .set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();

    // The peer has three threads:
    // 1) listens on the network for encapsulated packets and decapsulates them
    // 2) listens on the iface for raw packets and encapsulates them
    // 3) times maintenance function responsible for state expiration

    {
    // 1) listens on the network for encapsulated packets and decapsulates them
        let network_socket = network_socket.try_clone().unwrap();
        let iface_socket = iface_socket.try_clone().unwrap();
        let peer = peer.clone();
        let close = close.clone();

        thread::spawn(move || loop {
            // Listen on the network
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut send_buf = [0u8; MAX_PACKET];

            let n = match network_socket.recv(&mut recv_buf) {
                Ok(n) => n,
                Err(_) => {
                    if close.load(Ordering::Relaxed) {
                        return;
                    }
                    continue;
                }
            };

            println!("recv network_socket");
            let mut temp_recv: [u8; 150] = [0u8;150];
            temp_recv.copy_from_slice(&recv_buf[0..150]);
            println!("     network_socket recv: {:?}", temp_recv);
            match peer.decapsulate(None, &recv_buf[..n], &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    // debug_listenning(packet);
                    network_socket.send(packet).unwrap();
                    // Send form queue?
                    loop {

                        let mut send_buf = [0u8; MAX_PACKET];
                        match peer.decapsulate(None, &[], &mut send_buf) {
                            TunnResult::WriteToNetwork(packet) => {
                                println!("Inner decapsulate WriteToNetwork");
                                let mut temp_recv  = [0u8;64];
                                temp_recv.copy_from_slice(&packet[0..64]);
                                println!("      {:?}", temp_recv);
                                println!("");
                                network_socket.send(packet).unwrap();
                            }
                            x => {
                                println!("Inner decapsulate");
                                println!("{:?}",x);
                                println!("");
                                break;
                            }
                        }
                    }
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    println!("Outer decapsulate WriteToTunnelV4");
                    println!("       {:?}", packet);
                    iface_socket.send(packet).unwrap();
                }
                TunnResult::WriteToTunnelV6(packet, _) => {
                    println!("Outer decapsulate WriteToTunnelV6");
                    iface_socket.send(packet).unwrap();
                }
                x => {
                    println!("Outer decapsulate Other");
                    println!("      {:?}",x);
                }
            }
        });
    }

    // 2) listens on the iface for raw packets and encapsulates them
    {
        let network_socket = network_socket.try_clone().unwrap();
        let iface_socket = iface_socket.try_clone().unwrap();
        let peer = peer.clone();
        let close = close.clone();

        thread::spawn(move || loop {
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut send_buf = [0u8; MAX_PACKET];

            let n = match iface_socket.recv(&mut recv_buf) {
                Ok(n) => n,
                Err(e) => {
                    // println!("ERROR RECEIVED iface: {}", e);
                    if close.load(Ordering::Relaxed) {
                        return;
                    }
                    continue;
                }
            };

            println!("Pre - Encapsulate WriteToNetwork");
            let mut temp_recv: [u8; 37] = [0u8;37];
            temp_recv.copy_from_slice(&recv_buf[0..37]);
            println!("     iface_socket recv: {:?}", temp_recv);
            match peer.encapsulate(&recv_buf[..n], &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    println!("Encapsulate WriteToNetwork");
                    println!("       {:?}", packet);
                    network_socket.send(packet).unwrap();
                }
                x => {
                    println!("Encapsulate other");
                    println!("       {:?}", x);
                }
            }
        });
    }

    // 3) times maintenance function responsible for state expiration
    thread::spawn(move || loop {
        if close.load(Ordering::Relaxed) {
            return;
        }

        let mut send_buf = [0u8; MAX_PACKET];
        match peer.update_timers(&mut send_buf) {
            TunnResult::WriteToNetwork(packet) => {
                network_socket.send(packet).unwrap();
            }
            x => {
                // no point printing here as maintenence functions spam hard           
                // println!("Thread 3 {:?}", x);
            }
        }

        thread::sleep(Duration::from_millis(200));
    });

    iface_socket_ret
}

#[derive(Debug, Deserialize)]
struct ClientConfig {
    private_key: String,
    public_key: String,
}
#[derive(Debug, Deserialize)]
struct WG_server {
    public_key: String,
    public_ip: String
}

fn get_client_keys() -> ClientConfig {
    let input_path = format!("{}/config/client_keys.ron", env!("CARGO_MANIFEST_DIR"));
    let f = File::open(&input_path).expect("Failed opening file");
    let config: ClientConfig  = match from_reader(f) {
        Ok(x) => x,
        Err(e) => {
            println!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };
    println!("Config: {:?}", &config);
    config
}

fn get_wg_server() -> WG_server {
    let input_path = format!("{}/config/wg_server.ron", env!("CARGO_MANIFEST_DIR"));
    let f = File::open(&input_path).expect("Failed opening file");
    let config: WG_server  = match from_reader(f) {
        Ok(x) => x,
        Err(e) => {
            println!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };
    println!("Config: {:?}", &config);
    config
}




fn to_ipv4(s: String) -> Ipv4Addr {

    let ints : Vec<u8> = s.split(".")
        .into_iter()
        .map(|x| {
            x.parse::<>().unwrap()
        })
        .collect();
    if ints.len() !=4 {
        panic!("IP format invalid, explode");
    }

    Ipv4Addr::new(ints[0],ints[1],ints[2],ints[3])
}

fn get_my_public_ip() -> Ipv4Addr {
    let ip:IP = reqwest::blocking::get("https://api.ipify.org?format=json")
        .unwrap()
        .json()
        .unwrap();
    to_ipv4(ip.ip)
}   

fn main(){
   println!("Start wg client");
    let c_key_pair = get_client_keys(); // client
    let server = get_wg_server();

    let server_pub_key = server.public_key;
    let server_ip = server.public_ip;
    let itr = 30;

    // let DEST_IP: Ipv4Addr = to_ipv4("127.0.0.1".into());
    // let SRC_IP : Ipv4Addr = to_ipv4("127.0.0.1".into());

    let DEST_IP: Ipv4Addr = to_ipv4(server_ip.clone());
    let SRC_IP : Ipv4Addr = get_my_public_ip();


    let c_addr = format!("0.0.0.0:9000");
    let w_addr = format!("{}:{}", server_ip, "51820");

    println!("=== Packet ===");
    println!("SRC_IP {}",SRC_IP);
    println!("DEST_IP {}",DEST_IP);
    println!("");
    println!("Server Lives on {}",w_addr);
    println!("Client Lives on {}",c_addr);
    println!("");

    let client_socket =
        UdpSocket::bind(&c_addr).unwrap_or_else(|e| panic!("UdpSocket {}: {}", c_addr, e));

    client_socket
        .connect(&w_addr)
        .unwrap_or_else(|e| panic!("connect {}: {}", w_addr, e));

    println!("After Connect");

    let close = Arc::new(AtomicBool::new(false));

    let c_iface = wireguard_test_peer(
        client_socket,
        &c_key_pair.private_key,
        &server_pub_key,
        Box::new(|e: &str| eprintln!("client: {}", e)),
        close.clone(),
    );

    c_iface
        .set_read_timeout(Some(Duration::from_millis(3000)))
        .unwrap();
    

    println!("Begin Ping Attempts");

    for i in 0..itr {

        // write_ipv4_ping(&c_iface, b"ping", i as u16, SRC_IP, to_ipv4("8.8.8.8".into()));
        write_ipv4_ping(&c_iface, b"ping", i as u16, SRC_IP, DEST_IP);

        let response = read_ipv4_ping(&c_iface, i as u16);
        println!("RESPONSE : {:?}",response);
        println!("------------------------------");
        println!("");
        println!("");
        println!("");

        thread::sleep(Duration::from_millis(300));
    }


    println!("After Iterations ");
    close.store(true, Ordering::Relaxed);
}
