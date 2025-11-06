pub mod errors;

use anyhow::Result;
use common::messages::KeepAliveType;
use common::{errors::*, messages::*};
use ipnet::Ipv4AddrRange;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};

#[derive(Debug)]
pub struct ClientConnection {
    pub assigned_ip: Ipv4Addr,
    pub sock_addr: SocketAddr,
    pub last_seen: Instant,
}

impl ClientConnection {
    pub fn update_last_seen(&mut self, instant: Instant) {
        self.last_seen = instant;
    }
}

pub async fn perform_client_handshake(
    socket: &UdpSocket,
    address_pool: &mut Ipv4AddrRange,
    peer: &SocketAddr,
    _client_hello: ClientHelloMessage,
) -> Result<Ipv4Addr> {
    if let Some(assigned_ip) = address_pool.next() {
        let server_hello = {
            let hello = ServerHelloMessage { assigned_ip };
            serde_json::to_vec(&hello).unwrap()
        };

        let len = socket.send_to(&server_hello[..], peer).await?;
        println!("[+] Wrote {len} bytes of sever_hello to {peer}");
        return Ok(assigned_ip);
    }

    Err(errors::NoAddressLeft.into())
}

pub fn add_client(
    known_conns: &mut HashMap<SocketAddr, Ipv4Addr>,
    ip_to_sock: &mut HashMap<Ipv4Addr, SocketAddr>,
    peer: SocketAddr,
    assigned_ip: Ipv4Addr,
) -> Result<()> {
    println!("[+] Adding new peer {peer} to hashset with IP {assigned_ip}");
    known_conns.insert(peer, assigned_ip);
    ip_to_sock.insert(assigned_ip, peer);
    Ok(())
}

pub async fn keep_alive(socket: &UdpSocket, peer: &SocketAddr) -> Result<()> {
    let keep_alive = {
        let msg = KeepAliveMessage {
            msg_type: KeepAliveType::Request,
        };
        serde_json::to_vec(&msg).unwrap()
    };

    match socket.send_to(&keep_alive[..], peer).await {
        Ok(_) => {
            let mut buf = [0; 1024];
            if let Ok((len, reply_peer)) =
                timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await?
            {
                if *peer != reply_peer {
                    return Err(UnexpectedSource.into());
                }

                let msg = serde_json::from_slice::<KeepAliveMessage>(&buf[..len])?;

                if msg.msg_type != KeepAliveType::Reply {
                    return Err(UnexpectedMessage.into());
                }
            }
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}

pub fn remove_connection(
    known_conns: &mut HashMap<SocketAddr, Ipv4Addr>,
    ip_to_sock: &mut HashMap<Ipv4Addr, SocketAddr>,
    peer: &SocketAddr,
    client_ip: &Ipv4Addr,
) {
    println!("[-] Removing {peer} from connections");
    let _ = known_conns.remove_entry(&peer);
    ip_to_sock.remove_entry(&client_ip);
}
