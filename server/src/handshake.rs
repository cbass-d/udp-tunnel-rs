use anyhow::Result;
use ipnet::Ipv4AddrRange;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

use crate::{ClientHelloMessage, ServerHelloMessage};

pub async fn run(
    socket: &UdpSocket,
    assigned_ip: Ipv4Addr,
    peer: &SocketAddr,
    _client_hello: ClientHelloMessage,
) -> Result<()> {
    let server_hello = {
        let hello = ServerHelloMessage { assigned_ip };
        serde_json::to_vec(&hello).unwrap()
    };

    let len = socket.send_to(&server_hello[..], peer).await?;
    println!("[+] Wrote {len} bytes of sever_hello to {peer}");

    Ok(())
}
