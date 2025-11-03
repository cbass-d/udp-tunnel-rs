use anyhow::Result;
use common::{ClientHelloMessage, ServerHelloMessage, errors::*};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

pub async fn perform_server_handshake(socket: &UdpSocket, server: SocketAddr) -> Result<Ipv4Addr> {
    println!("[*] Connecting to server...");
    socket.connect(server).await?;

    let cli_hello = {
        let hello = ClientHelloMessage {};
        serde_json::to_vec(&hello).unwrap()
    };

    let len = socket.send(&cli_hello[..]).await?;
    println!("[*] Sent client_hello of {len} bytes");

    let mut sock_buf = [0; 1024];

    println!("[*] Waiting for server_hello...");
    let (len, peer) = socket.recv_from(&mut sock_buf[..]).await?;

    if peer != server {
        println!("[-] Unexpected source address of message");
        return Err(UnexpectedSource.into());
    }

    let server_hello = serde_json::from_slice::<ServerHelloMessage>(&sock_buf[..len]).unwrap();
    let assigned_addr = server_hello.assigned_ip;
    println!("[*] Recived server_hello with assigned ip: {assigned_addr}");

    Ok(assigned_addr)
}
