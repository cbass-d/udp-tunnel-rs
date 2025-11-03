use anyhow::Result;
use clap::Parser;
use clap_derive::Parser;
use cli_log::*;
use client::perform_server_handshake;
use futures::{SinkExt, StreamExt};
use pnet_packet::{
    Packet,
    ipv4::{self},
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time;
use tokio_util::sync::CancellationToken;

use tun::{self, AbstractDevice, BoxError, Configuration};

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short, long)]
    server: SocketAddr,

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

    start(token).await?;
    ctrlc.await?;
    Ok(())
}

async fn start(token: CancellationToken) -> Result<(), BoxError> {
    let args = Args::parse();
    let tun_name = args.tun_name;
    let port = args.port;
    let server = args.server;

    let bind_address = format!("0.0.0.0:{port}");
    let socket = UdpSocket::bind(bind_address).await?;
    println!(
        "[*] Binded to UDP Socket at {}",
        socket.local_addr().unwrap()
    );

    // Peform handshake with server
    let mut max_retries = 3;
    let assigned_addr = loop {
        match perform_server_handshake(&socket, server).await {
            Ok(assigned_addr) => break assigned_addr,
            Err(e) => {
                if max_retries == 0 {
                    panic!("[-] Server handshake failed: {e}");
                } else {
                    println!("[*] Re-attempting server handshake");
                    max_retries -= 1;
                }
            }
        }
    };

    let mut config = Configuration::default();
    config
        .tun_name(tun_name.unwrap_or("".to_string()))
        .address(assigned_addr)
        .netmask((255, 255, 255, 0))
        .up();

    let dev = tun::create_as_async(&config).unwrap();

    println!(
        "[+] Configured new tun device with name: {} and address: {}",
        dev.tun_name().unwrap(),
        dev.address().unwrap()
    );

    let mut framed_dev = dev.into_framed();

    let mut interval = time::interval(Duration::from_secs(3));

    let mut sock_buf = [0; 1024];

    let mut max_retries = 3;
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                println!("[-] Quitting");
                break;
            },
            _ = interval.tick() => {
            },
            result = socket.recv_from(&mut sock_buf) => {
                let (len, peer) = result?;
                println!("[*] Recv {len} from {peer}");

                let ipv4_packet = ipv4::Ipv4Packet::new(&sock_buf[..len]).unwrap();

                framed_dev.send(ipv4_packet.packet().to_vec()).await?;
            },
            Some(packet) = framed_dev.next() => {
                if let Ok(packet) = packet {
                    let ipv4_packet = ipv4::Ipv4Packet::new(&packet[..]).unwrap();
                    match packet[0] >> 4 {
                        4 => {},
                        _ => continue,
                    }

                    // Send through regular UDP Socket
                    match socket.send(ipv4_packet.packet()).await {
                        Ok(len) => {
                            println!("[*] Sent {len} bytes");
                        },
                        Err(e) => {
                            println!("[-] Error: {e}");
                            max_retries -= 1;
                            if  max_retries == 0 {
                                panic!("{e}");
                            }
                        },
                    }
                }
            },
        }
    }

    Ok(())
}
