use anyhow::Result;
use common::messages::{SocketMessages, TunMessages};
use futures::{SinkExt, StreamExt};
use pnet_packet::{Packet, ipv4};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tokio_util::{codec::Framed, sync::CancellationToken};
use tun::{AbstractDevice, AsyncDevice, Configuration, TunPacketCodec};

use crate::manager::ManagerMessages;

pub fn create_tun(
    tun_name: Option<String>,
    assigned_addr: Ipv4Addr,
) -> Result<Framed<AsyncDevice, TunPacketCodec>> {
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

    let framed_dev = dev.into_framed();
    Ok(framed_dev)
}

pub async fn run(
    mut framed_tun: Framed<AsyncDevice, TunPacketCodec>,
    _manager_tx: mpsc::UnboundedSender<ManagerMessages>,
    socket_tx: mpsc::UnboundedSender<SocketMessages>,
    mut tun_rx: mpsc::UnboundedReceiver<TunMessages>,
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

                    let write_packet = SocketMessages::WritePacketToServer(ipv4_packet.packet().to_vec());
                    socket_tx.send(write_packet)?;
                }

            },
            message = tun_rx.recv() => {
                match message {
                    Some(TunMessages::WritePacket(packet)) => {
                        framed_tun.send(packet).await?;
                    },
                    _ => {},
                }
            },
        }
    }

    Ok(())
}
