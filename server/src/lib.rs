pub mod errors;
pub mod handshake;
pub mod keep_alive;
pub mod manager;
pub mod registry;
pub mod socket;
pub mod tun;

pub use common::{errors::*, messages::*};

use anyhow::Result;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, sync::mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    manager::ManagerMessages, registry::ClientRegistry, socket::SocketMessage, tun::TunMessage,
};

pub async fn start(
    token: CancellationToken,
    tun_name: Option<String>,
    address: Ipv4Addr,
    port: u16,
) -> Result<()> {
    let bind_adress = format!("0.0.0.0:{port}");
    let socket = UdpSocket::bind(bind_adress).await?;
    println!(
        "[*] Binded to UDP Socket at {}",
        socket.local_addr().unwrap()
    );

    let tun_device = tun::create_tun(tun_name, address)?;

    let (tun_tx, tun_rx) = mpsc::unbounded_channel::<TunMessage>();
    let (socket_tx, socket_rx) = mpsc::unbounded_channel::<SocketMessage>();
    let framed_device = tun_device.into_framed();

    let mut sock_buf = [0; 2048];

    let client_registry: Arc<ClientRegistry> = Arc::new(ClientRegistry::new());

    let mut interval = tokio::time::interval(Duration::from_secs(5));

    let (manager_tx, manager_rx) = mpsc::unbounded_channel::<ManagerMessages>();

    let manager_task = tokio::task::spawn(manager::run(manager_rx, token.clone()));

    let tun_socket_task = tokio::task::spawn(tun::run(
        framed_device,
        manager_tx.clone(),
        socket_tx.clone(),
        tun_rx,
        token.clone(),
    ));

    let udp_socket_task = tokio::task::spawn(socket::run(
        socket,
        manager_tx.clone(),
        tun_tx.clone(),
        socket_rx,
        token.clone(),
    ));

    token.cancelled().await;

    // Main event loop
    //loop {
    //    tokio::select! {
    //        _ = token.cancelled() => {
    //            println!("[*] Quitting");
    //            break;
    //        },
    //        result = socket.recv_from(&mut sock_buf) => {
    //            else {
    //                let raw_packet = &sock_buf[..len];

    //                let client = known_conns.get_mut(&peer).unwrap();
    //                client.update_last_seen(Instant::now());
    //                match raw_packet[0] >> 4 {
    //                    4 => {
    //                        let ipv4_packet = ipv4::Ipv4Packet::new(&raw_packet[..]).unwrap();
    //                        let des = ipv4_packet.get_destination();

    //                        if !ip_to_sock.contains_key(&des) {
    //                            framed_tun.send(ipv4_packet.packet().to_vec()).await?;
    //                            continue;
    //                        }

    //                        let peer = ip_to_sock[&des];
    //                        let _len = socket.send_to(ipv4_packet.packet(), peer).await?;
    //                    },
    //                    6 => {
    //                    },
    //                    _ => {},
    //                }
    //            }

    //        },
    //        Some(packet) = framed_tun.next() => {
    //            if let Ok(packet) = packet {
    //                let ipv4_packet = ipv4::Ipv4Packet::new(&packet[..]).unwrap();

    //                let dst = ipv4_packet.get_destination();

    //                if ip_to_sock.contains_key(&dst) {
    //                    let peer = ip_to_sock[&dst];
    //                    let _len = socket.send_to(ipv4_packet.packet(), peer).await?;
    //                }
    //            }
    //        },
    //    }
    //}

    Ok(())
}
