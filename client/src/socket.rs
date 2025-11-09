use anyhow::Result;
use common::messages::{KeepAliveMessage, KeepAliveType, SocketMessages, TunMessages};
use pnet_packet::{Packet, ipv4};
use tokio::{net::UdpSocket, sync::mpsc};
use tokio_util::sync::CancellationToken;

use crate::manager::ManagerMessages;

pub async fn run(
    socket: UdpSocket,
    _manager_tx: mpsc::UnboundedSender<ManagerMessages>,
    tun_tx: mpsc::UnboundedSender<TunMessages>,
    mut socket_rx: mpsc::UnboundedReceiver<SocketMessages>,
    cancel_token: CancellationToken,
) -> Result<()> {
    // Task responsible for UDP socket:
    // * listen for packets from server
    // * send packets to server
    // * forwards packets to the TUN task when needed
    let mut sock_buf = [0; 2048];
    let mut max_retries = 3;
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                println!("[-] Shutting down udp socket...");
                break;
            },
            Ok((len, peer)) = socket.recv_from(&mut sock_buf[..]) => {
                println!("[*] Recv {len} from {peer}");
                if let Ok(keep_alive) = serde_json::from_slice::<KeepAliveMessage>(&sock_buf[..len]) {
                    if keep_alive.msg_type == KeepAliveType::Request {
                        let keep_alive = {
                            let msg = KeepAliveMessage {msg_type: KeepAliveType::Reply };
                            serde_json::to_vec(&msg).unwrap()
                        };
                        socket.send(&keep_alive[..]).await?;
                    }

                    continue;
                }

                let ipv4_packet = ipv4::Ipv4Packet::new(&sock_buf[..len]).unwrap();
                let write_packet = TunMessages::WritePacket(ipv4_packet.packet().to_vec());
                tun_tx.send(write_packet)?;
            },
            Some(message) = socket_rx.recv() => {
                match message {
                    SocketMessages::WritePacketToServer(packet) => {
                        match socket.send(&packet).await {
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
                    },
                    _ => {},
                }
            },
        }
    }

    Ok(())
}
