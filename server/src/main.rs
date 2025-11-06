use futures::{SinkExt, StreamExt};
use server::{
    ClientConnection, add_client, keep_alive, perform_client_handshake, remove_connection,
};
use std::sync::Arc;
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::Result;
use clap::Parser;
use clap_derive::Parser;
use cli_log::*;
use pnet_packet::Packet;
use pnet_packet::ipv4::{self};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tun::{self, AbstractDevice, BoxError, Configuration};

use common::messages::*;

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short, long)]
    address: Ipv4Addr,

    #[arg(short, long)]
    tun_name: Option<String>,

    #[arg(short, long)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    init_cli_log!();
    let token = CancellationToken::new();
    let token_clone = token.clone();

    let ctrlc = ctrlc2::AsyncCtrlC::new(move || {
        token_clone.cancel();
        true
    })?;

    println!("[*] Starting server...");
    let args = Args::parse();
    let tun_name = args.tun_name;
    let address = args.address;
    let port = args.port;
    start(token, tun_name, address, port).await?;
    ctrlc.await?;
    Ok(())
}

// Main function for starting the server
async fn start(
    token: CancellationToken,
    tun_name: Option<String>,
    address: Ipv4Addr,
    port: u16,
) -> Result<(), BoxError> {
    let bind_adress = format!("0.0.0.0:{port}");
    let socket = UdpSocket::bind(bind_adress).await?;
    println!(
        "[*] Binded to UDP Socket at {}",
        socket.local_addr().unwrap()
    );

    let mut config = Configuration::default();
    config
        .tun_name(tun_name.unwrap_or("".to_string()))
        .up()
        .address(address)
        .netmask((255, 255, 255, 0));

    let tun = tun::create_as_async(&config).unwrap();
    println!(
        "[+] Creating tun device with name : {}, and address: {}",
        tun.tun_name().unwrap(),
        tun.address().unwrap()
    );

    let mut framed_tun = tun.into_framed();

    let mut sock_buf = [0; 2048];

    // Stuff for client connections
    let mut known_conns: HashMap<SocketAddr, ClientConnection> = HashMap::new();
    let mut ip_to_sock: HashMap<Ipv4Addr, SocketAddr> = HashMap::new();
    let mut dead_connections: HashSet<(SocketAddr, Ipv4Addr)> = HashSet::new();
    let mut address_pool =
        ipnet::Ipv4AddrRange::new("10.0.0.2".parse().unwrap(), "10.0.0.10".parse().unwrap());

    let mut interval = tokio::time::interval(Duration::from_secs(5));

    // Main event loop
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                println!("[*] Quitting");
                break;
            },
            result = socket.recv_from(&mut sock_buf) => {
                let (len, peer) = result?;
                if !known_conns.contains_key(&peer) {
                    // Peform handshake with client
                    if let Ok(client_hello) = serde_json::from_slice::<ClientHelloMessage>(&sock_buf[..len]) {
                        println!("[*] Performing handshake with client...");
                        match perform_client_handshake(&socket, &mut address_pool, &peer, client_hello).await {
                                Ok(client_addr) => {
                                    println!("[+] Handshake with client successful");
                                    println!("[+] Adding new peer {peer} to hashset with IP {client_addr}");
                                    let client_connection = ClientConnection {
                                        sock_addr: peer,
                                        assigned_ip: client_addr,
                                        last_seen: Instant::now(),
                                    };
                                    known_conns.insert(peer, client_connection);
                                    ip_to_sock.insert(client_addr, peer);
                                },
                                Err(e) => println!("[-] Client handshake error: {e}"),
                        }
                    }
                }
                else {
                    let raw_packet = &sock_buf[..len];

                    let client = known_conns.get_mut(&peer).unwrap();
                    client.update_last_seen(Instant::now());
                    match raw_packet[0] >> 4 {
                        4 => {
                            let ipv4_packet = ipv4::Ipv4Packet::new(&raw_packet[..]).unwrap();
                            let des = ipv4_packet.get_destination();

                            if !ip_to_sock.contains_key(&des) {
                                framed_tun.send(ipv4_packet.packet().to_vec()).await?;
                                continue;
                            }

                            let peer = ip_to_sock[&des];
                            let _len = socket.send_to(ipv4_packet.packet(), peer).await?;
                        },
                        6 => {
                        },
                        _ => {},
                    }
                }

            },
            Some(packet) = framed_tun.next() => {
                if let Ok(packet) = packet {
                    let ipv4_packet = ipv4::Ipv4Packet::new(&packet[..]).unwrap();

                    let dst = ipv4_packet.get_destination();

                    if ip_to_sock.contains_key(&dst) {
                        let peer = ip_to_sock[&dst];
                        let _len = socket.send_to(ipv4_packet.packet(), peer).await?;
                    }
                }
            },
            _ = interval.tick() => {
                for (peer, client) in known_conns.iter() {
                    match keep_alive(&socket, peer).await {
                        Ok(()) => {},
                        Err(_) => {
                            println!("[-] Keep alive for {peer} ({}) failed", client.assigned_ip);
                            dead_connections.insert((*peer, client.assigned_ip));
                        },
                    }
                }

                for (peer, client_ip) in dead_connections.iter() {
                    println!("[-] Removing {peer} from connections");
                    let _ = known_conns.remove_entry(&peer);
                    ip_to_sock.remove_entry(&client_ip);
                }
                dead_connections.clear();
            },
        }
    }

    Ok(())
}
