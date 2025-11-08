use pnet_packet::{Packet, ipv4};
use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use common::messages::ClientHelloMessage;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

use crate::{
    handshake, keep_alive, manager::ManagerMessages, registry::ClientConnection, tun::TunMessage,
};

pub enum SocketMessage {
    WritePacket(SocketAddr, Vec<u8>),
}

pub async fn run(
    socket: UdpSocket,
    manager_tx: mpsc::UnboundedSender<ManagerMessages>,
    tun_tx: mpsc::UnboundedSender<TunMessage>,
    mut socket_rx: mpsc::UnboundedReceiver<SocketMessage>,
    cancel_token: CancellationToken,
) -> Result<()> {
    let mut sock_buf = [0; 2048];

    let mut interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                println!("[-] Shutting down udp socket...");
                break;
            },
            result = socket.recv_from(&mut sock_buf[..]) => {
                if let Ok((len, peer)) = result {
                    let (tx, rx) = oneshot::channel::<Option<ClientConnection>>();

                    let get_client = ManagerMessages::GetClient(peer, tx);
                    manager_tx.send(get_client)?;

                    let res = rx.await?;
                    match res {
                        Some(client) => {
                            let update_last_seen = ManagerMessages::UpdateLastSeen(client.sock_addr);
                            manager_tx.send(update_last_seen)?;

                            let raw_packet = &sock_buf[..len];

                            match raw_packet[0] >> 4 {
                                4 => {
                                    let ipv4_packet = ipv4::Ipv4Packet::new(&raw_packet[..]).unwrap();
                                    let des = ipv4_packet.get_destination();

                                    let (tx, rx) = oneshot::channel::<Option<SocketAddr>>();
                                    let get_route = ManagerMessages::ResolveRoute(des, tx);
                                    manager_tx.send(get_route)?;

                                    if let Some(route) = rx.await? {
                                        let _ = socket.send_to(ipv4_packet.packet(), route).await?;
                                    }
                                    else {
                                        println!("sending to {des} from {}", client.assigned_ip);
                                        let write_packet = TunMessage::WritePacket(ipv4_packet.packet().to_vec());
                                        let _ = tun_tx.send(write_packet)?;
                                    }

                                },
                                5 => {},
                                _ => {},
                            }
                        },
                        None => {
                            if let Ok(client_hello) = serde_json::from_slice::<ClientHelloMessage>(&sock_buf[..len]) {
                                let (tx, rx) = oneshot::channel::<ClientConnection>();
                                let add_client = ManagerMessages::AddClient(peer, tx);
                                manager_tx.send(add_client)?;
                                let client = rx.await?;

                                let handshake_res = handshake::run(&socket, client.assigned_ip, &client.sock_addr, client_hello).await;
                                match handshake_res {
                                    Ok(()) => {},
                                    Err(e) => {
                                        println!("[-] Handshake failed for peer {peer}: {e}");
                                    },
                                }
                            }
                        },
                    }
                }
            },
            message = socket_rx.recv() => {
                match message {
                    Some(SocketMessage::WritePacket(peer, packet)) => {
                        let _ = socket.send_to(&packet[..], peer).await?;
                    },
                    _ => {},
                }
            },
            _ = interval.tick() => {
                let (tx, rx) = oneshot::channel::<Vec<ClientConnection>>();
                let list_clients = ManagerMessages::GetAllClients(tx);
                manager_tx.send(list_clients)?;

                let clients = rx.await?;
                for client in clients {
                    match keep_alive::run(&socket, &client.sock_addr).await {
                        Ok(()) => {},
                        Err(e) => {
                            println!("[-] Keep alive for {} ({}) failed: {e}", client.assigned_ip, client.sock_addr);

                            let remove_client = ManagerMessages::RemoveClient(client.sock_addr);
                            manager_tx.send(remove_client).unwrap();
                        },
                    }
                }
            }
        }
    }

    Ok(())
}
