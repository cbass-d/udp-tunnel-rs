use anyhow::Result;
use futures::{SinkExt, StreamExt};
use pnet_packet::{Packet, ipv4};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::sync::{mpsc, oneshot};
use tokio_util::{codec::Framed, sync::CancellationToken};
use tun::{AbstractDevice, AsyncDevice, Configuration, TunPacketCodec};

use crate::{manager::ManagerMessages, socket::SocketMessage};

pub enum TunMessage {
    WritePacket(Vec<u8>),
}

pub fn create_tun(tun_name: Option<String>, address: Ipv4Addr) -> Result<AsyncDevice> {
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

    Ok(tun)
}

pub async fn run(
    mut framed_tun: Framed<AsyncDevice, TunPacketCodec>,
    manager_tx: mpsc::UnboundedSender<ManagerMessages>,
    socket_tx: mpsc::UnboundedSender<SocketMessage>,
    mut tun_rx: mpsc::UnboundedReceiver<TunMessage>,
    cancel_token: CancellationToken,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                println!("[-] Shutting down tun task...");
                break;
            },
            Some(packet) = framed_tun.next() => {
                if let Ok(packet) = packet {
                    let ipv4_packet = ipv4::Ipv4Packet::new(&packet[..]).unwrap();

                    let dest = ipv4_packet.get_destination();

                    let (tx, rx) = oneshot::channel::<Option<SocketAddr>>();
                    let get_route = ManagerMessages::ResolveRoute(dest, tx);
                    manager_tx.send(get_route)?;

                    if let Some(route) = rx.await? {
                        println!("sending packet to {dest}/{route}");
                        let write_packet = SocketMessage::WritePacket(route, ipv4_packet.packet().to_vec());
                        socket_tx.send(write_packet)?;
                    }
                }

            },
            message = tun_rx.recv() => {
                match message {
                    Some(TunMessage::WritePacket(packet)) => {
                        let _ = framed_tun.send(packet).await?;
                    },
                    _ => {},
                }
            },
        }
    }

    Ok(())
}
