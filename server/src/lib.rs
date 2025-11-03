pub mod errors;

use anyhow::Result;
use common::{ClientHelloMessage, ServerHelloMessage, errors::*};
use ipnet::Ipv4AddrRange;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

pub struct ClientConnection {
    pub assigned_ip: Ipv4Addr,
    pub sock_addr: SocketAddr,
}

pub async fn perform_client_handshake(
    socket: &UdpSocket,
    address_pool: &mut Ipv4AddrRange,
    peer: &SocketAddr,
    client_hello: ClientHelloMessage,
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
