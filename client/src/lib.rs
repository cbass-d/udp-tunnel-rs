pub mod handshake;
pub mod manager;
pub mod socket;
pub mod tun;

use anyhow::Result;
use cli_log::*;
use common::messages::*;
use std::net::SocketAddr;
use tokio::{net::UdpSocket, sync::mpsc};
use tokio_util::sync::CancellationToken;

use crate::manager::ManagerMessages;

pub async fn run(
    tun_name: Option<String>,
    port: u16,
    server: SocketAddr,
    token: CancellationToken,
) -> Result<()> {
    let bind_address = format!("0.0.0.0:{port}");
    let socket = UdpSocket::bind(bind_address).await?;
    println!(
        "[*] Binded to UDP Socket at {}",
        socket.local_addr().unwrap()
    );

    // Peform handshake with server (3 max-retries)
    let mut max_retries = 3;
    let assigned_addr = loop {
        match handshake::run(&socket, server).await {
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

    // Channels for message/packet passing:
    // * messages for manager
    // * passing packets between the tun interface and the UDP socket facing the server
    let (manager_tx, _manager_rx) = mpsc::unbounded_channel::<ManagerMessages>();
    let (tun_tx, tun_rx) = mpsc::unbounded_channel::<TunMessages>();
    let (socket_tx, socket_rx) = mpsc::unbounded_channel::<SocketMessages>();

    let framed_tun = tun::create_tun(tun_name, assigned_addr)?;

    // Spawn each of the task in a task set, for easier management of joining,
    // aborting, logging, etc.
    let mut task_set = tokio::task::JoinSet::new();

    //let _manager_task = task_set.spawn(manager::run(manager_rx, token.clone()));

    let _tun_task = task_set.spawn(tun::run(
        framed_tun,
        manager_tx.clone(),
        socket_tx.clone(),
        tun_rx,
        token.clone(),
    ));

    let _udp_socket_task = task_set.spawn(socket::run(
        socket,
        manager_tx.clone(),
        tun_tx.clone(),
        socket_rx,
        token.clone(),
    ));

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                println!("[-] Quitting");
                break;
            },
            Some(res) = task_set.join_next_with_id() => {
                match res {
                    Ok((id, t)) if t.is_err() => {
                        error!("task with id {id} failed: {t:?}");
                        token.cancel();
                    },
                    Ok((id, t)) if t.is_ok() => {
                        info!("task with id {id} finished");
                        token.cancel();
                    },
                    Err(e) => {
                        error!("task join falied: {e}");
                        break;
                    }
                    _ => {},
                }
            },
        }
    }

    task_set.join_all().await;
    Ok(())
}
