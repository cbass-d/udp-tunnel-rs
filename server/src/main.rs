use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tun::{self, AbstractDevice, BoxError, Configuration};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let token = CancellationToken::new();
    let token_clone = token.clone();

    let ctrlc = ctrlc2::AsyncCtrlC::new(move || {
        token_clone.cancel();
        true
    })?;

    start(token).await?;
    ctrlc.await?;
    Ok(())
}

async fn start(token: CancellationToken) -> Result<(), BoxError> {
    let mut config = Configuration::default();

    config
        .address((10, 0, 0, 2))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .up();

    let mut dev = tun::create_as_async(&config)?;
    let size = dev.mtu()? as usize + tun::PACKET_INFORMATION_LENGTH;

    let socket = UdpSocket::bind("localhost:9899").await?;
    let remote_peer = "localhost:9898";

    let mut tun_buf = vec![0; 4096];
    let mut socket_buf = vec![0; 4096];

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                println!("Quitting");
                break;
            },
            result = socket.recv_from(&mut socket_buf) => {
                let (len, peer) = result?;
                println!("UDP -> TUN: {len} bytes from {peer}");

                if let Some(packet) = pnet_packet::ipv4::Ipv4Packet::new(&socket_buf[..len]) {
                    println!("IPv4: {} -> {}", packet.get_source(), packet.get_destination());
                }

                else if let Some(packet) = pnet_packet::ipv6::Ipv6Packet::new(&socket_buf[..len]) {
                    println!("IPv6: {} -> {}", packet.get_source(), packet.get_destination());
                }

                dev.write(&socket_buf[..len]).await?;

            },
            result = dev.read(&mut tun_buf) => {
                let len = result?;
                println!("TUN -> UDP: {len} btyes");

                if let Some(packet) = pnet_packet::ipv4::Ipv4Packet::new(&tun_buf[..len]) {
                    println!("IPv4: {} -> {}", packet.get_source(), packet.get_destination());
                }

                else if let Some(packet) = pnet_packet::ipv6::Ipv6Packet::new(&tun_buf[..len]) {
                    println!("IPv6: {} -> {}", packet.get_source(), packet.get_destination());
                }

                socket.send_to(&tun_buf[..len], remote_peer).await?;
            },
        }
    }

    Ok(())
}
