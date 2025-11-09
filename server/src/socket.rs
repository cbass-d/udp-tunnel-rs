use cli_log::info;
use pnet_packet::{Packet, ipv4};
use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use common::messages::{ClientHelloMessage, SocketMessages, TunMessages};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

use crate::{handshake, keep_alive, manager::ManagerMessages, registry::ClientConnection};

pub async fn run(
    socket: UdpSocket,
    manager_tx: mpsc::UnboundedSender<ManagerMessages>,
    tun_tx: mpsc::UnboundedSender<TunMessages>,
    mut socket_rx: mpsc::UnboundedReceiver<SocketMessages>,
    cancel_token: CancellationToken,
) -> Result<()> {
    // Task responsible for UDP socket:
    // * listens for client connections
    // * forwards packets to the TUN task when needed
    // * forwards packets back to client
    // * implements keep alive mechanism
    let mut sock_buf = [0; 2048];
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                println!("[-] Shutting down udp socket...");
                break;
            },
            Ok((len, peer)) = socket.recv_from(&mut sock_buf[..]) => {
                let (tx, rx) = oneshot::channel::<Option<ClientConnection>>();
                let get_client = ManagerMessages::GetClient(peer, tx);
                manager_tx.send(get_client)?;

                // Match if client already exists, if not add to client registry
                let client_res = rx.await?;
                match client_res {
                    Some(client) => {
                        let update_last_seen = ManagerMessages::UpdateLastSeen(client.sock_addr);
                        manager_tx.send(update_last_seen)?;

                        // Match IP Version
                        let raw_packet = &sock_buf[..len];
                        match raw_packet[0] >> 4 {
                            4 => {
                                let ipv4_packet = ipv4::Ipv4Packet::new(raw_packet).unwrap();
                                let des = ipv4_packet.get_destination();

                                // If packet is for one of the clients send through UDP connection,
                                // else write to TUN task
                                let (tx, rx) = oneshot::channel::<Option<SocketAddr>>();
                                let get_route = ManagerMessages::ResolveRoute(des, tx);
                                manager_tx.send(get_route)?;

                                if let Some(route) = rx.await? {
                                    info!("received packet from client: to {des} from {}", client.assigned_ip);
                                    let _ = socket.send_to(ipv4_packet.packet(), route).await?;
                                }
                                else {
                                    info!("packet with no route found");
                                    let write_packet = TunMessages::WritePacket(ipv4_packet.packet().to_vec());
                                    tun_tx.send(write_packet)?;
                                }

                            },
                            6 => {},
                            _ => {},
                        }
                    }
                    None => {
                        // Check for valid client hello and perform handshake (assignment of ip to
                        // client)
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
         },
         Some(message) = socket_rx.recv() => {
             match message {
                    SocketMessages::WritePacket(peer, packet) => {
                        let _ = socket.send_to(&packet[..], peer).await?;
                    },
                    _ => {},
                }
            },
            _ = interval.tick() => {
                let (tx, rx) = oneshot::channel::<Vec<ClientConnection>>();
                let list_clients = ManagerMessages::GetAllClients(tx);
                manager_tx.send(list_clients)?;

                // Keep alive for all clients in registry
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
