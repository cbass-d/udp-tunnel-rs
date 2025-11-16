use anyhow::Result;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use log::{error, info, warn};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeState {
    Started,
    Done,
    None,
}

#[derive(thiserror::Error, Debug)]
pub enum WgSocketError {
    #[error("Timeout received")]
    Timeout,
    #[error("Socket not binded")]
    NotBinded,
    #[error("Handshake not completed")]
    NoHandshake,
}

pub struct WgSocket {
    tunn: Tunn,
    socketaddr: SocketAddr,
    socket: Option<UdpSocket>,
    peer_socketaddr: SocketAddr,
    handshake: HandshakeState,
}

impl WgSocket {
    pub fn new(
        static_private: x25519::StaticSecret,
        index: u32,
        socketaddr: SocketAddr,
        peer_static_public: x25519::PublicKey,
        peer_socketaddr: SocketAddr,
    ) -> Self {
        let tunn = Tunn::new(static_private, peer_static_public, None, None, index, None).unwrap();

        Self {
            tunn,
            socketaddr,
            socket: None,
            peer_socketaddr,
            handshake: HandshakeState::None,
        }
    }

    pub async fn bind(&mut self) -> Result<()> {
        if self.socket.is_none() {
            let socket = UdpSocket::bind(self.socketaddr).await?;
            self.socket = Some(socket);
            info!("UDP socket binded to {}", self.socketaddr);
        } else {
            warn!("Attempted to rebind socket");
        }

        Ok(())
    }

    pub async fn connect(&self) -> Result<()> {
        if let Some(ref socket) = self.socket {
            socket.connect(self.peer_socketaddr).await?;
            info!(
                "Connected to peer: {} -> {}",
                self.socketaddr, self.peer_socketaddr
            );
        } else {
            error!("Connect failed: no binded socket");
            return Err(WgSocketError::NotBinded.into());
        }

        Ok(())
    }

    pub async fn initiate_handshake(&mut self) -> Result<()> {
        if self.socket.is_none() {
            error!("Handshake initiation failed: no binded socket");
            return Err(WgSocketError::NotBinded.into());
        }
        let socket = self.socket.as_ref().unwrap();

        info!("Initiating handshake");
        self.handshake = HandshakeState::Started;

        // Create and send handshake init
        let mut dst = vec![0u8; 2048];
        let handshake_init = self.tunn.format_handshake_initiation(&mut dst, false);
        let handshake_init = if let TunnResult::WriteToNetwork(data) = handshake_init {
            data
        } else {
            unreachable!();
        };
        socket.send(handshake_init).await?;

        info!("Handhsake init message sent");

        // Recieve and parse response
        let mut buf = vec![0u8; 2048];
        if let Ok(Ok(len)) = timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
            info!("Handshake resp message received");

            let resp = self.tunn.decapsulate(None, &buf[..len], &mut dst);
            // Create and send keep alive
            let keepalive = if let TunnResult::WriteToNetwork(data) = resp {
                data
            } else {
                unreachable!();
            };
            socket.send(keepalive).await?;

            info!("Keepalive message sent");
        } else {
            return Err(WgSocketError::Timeout.into());
        }

        self.handshake = HandshakeState::Done;
        Ok(())
    }

    pub async fn handshake_response(&mut self) -> Result<()> {
        if self.socket.is_none() {
            error!("Handshake response failed: no binded socket");
            return Err(WgSocketError::NotBinded.into());
        }
        let socket = self.socket.as_ref().unwrap();

        let mut buf = vec![0u8; 2048];

        self.handshake = HandshakeState::Started;
        // Receive and parse handshake initiation
        if let Ok(Ok(len)) = timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
            info!("Handshake init message received");

            let handshake_init = &buf[..len];

            // Create and send handshake response
            let mut dst = [0u8; 2048];
            let handshake_resp = self.tunn.decapsulate(None, handshake_init, &mut dst);

            let handshake_resp = if let TunnResult::WriteToNetwork(data) = handshake_resp {
                data
            } else {
                unreachable!();
            };

            socket.send(handshake_resp).await?;

            info!("Handshake message sent");

            // Recieve and parse keepalive
            if let Ok(Ok(len)) = timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
                info!("Keepalive message received");

                let _keepalive = &buf[..len];
            }
        }

        self.handshake = HandshakeState::Done;
        Ok(())
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<usize> {
        if self.handshake != HandshakeState::Done {
            error!("Write failed: no handshake");
            return Err(WgSocketError::NoHandshake.into());
        }

        let mut dst = vec![0u8; 2048];
        let enc_data = self.tunn.encapsulate(data, &mut dst);

        let enc_data = if let TunnResult::WriteToNetwork(data) = enc_data {
            data
        } else {
            unreachable!();
        };

        let socket = self.socket.as_ref().unwrap();

        let len = socket.send(enc_data).await?;

        Ok(len)
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.handshake != HandshakeState::Done {
            error!("Write failed: no handshake");
            return Err(WgSocketError::NoHandshake.into());
        }

        let socket = self.socket.as_ref().unwrap();
        let len = socket.recv(buf).await?;
        let mut dst = vec![0u8; 2048];
        let data = self.tunn.decapsulate(None, &buf[..len], &mut dst);
        let data = if let TunnResult::WriteToTunnelV4(data, _src) = data {
            data
        } else {
            unreachable!();
        };

        let out_len = data.len();
        buf[..out_len].copy_from_slice(data);
        Ok(out_len)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use boringtun::x25519;
    use rand_core::{OsRng, RngCore};
    use tokio::task::JoinSet;

    use crate::WgSocket;

    async fn create_socket_pair() -> (WgSocket, WgSocket) {
        let addr_a = SocketAddr::from(([127, 0, 0, 1], 6001));
        let addr_b = SocketAddr::from(([127, 0, 0, 1], 6002));

        let secret_a = x25519::StaticSecret::random_from_rng(OsRng);
        let public_a = x25519::PublicKey::from(&secret_a);
        let idx_a = OsRng.next_u32();

        let secret_b = x25519::StaticSecret::random_from_rng(OsRng);
        let public_b = x25519::PublicKey::from(&secret_b);
        let idx_b = OsRng.next_u32();

        let mut wg_socket_a = WgSocket::new(secret_a, idx_a, addr_a, public_b, addr_b);
        let mut wg_socket_b = WgSocket::new(secret_b, idx_b, addr_b, public_a, addr_a);

        assert!(wg_socket_a.bind().await.is_ok());
        assert!(wg_socket_a.connect().await.is_ok());
        assert!(wg_socket_b.bind().await.is_ok());
        assert!(wg_socket_b.connect().await.is_ok());

        (wg_socket_a, wg_socket_b)
    }

    fn create_udp_packet() -> Vec<u8> {
        let header =
            etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 5).udp(6000, 6001);
        let payload = [0, 1, 2, 3, 4];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();

        packet
    }

    #[tokio::test]
    async fn full_handshake_and_packet() {
        let (mut wg_socket_a, mut wg_socket_b) = create_socket_pair().await;

        let udp_packet = create_udp_packet();
        let udp_packet_cl = udp_packet.clone();
        let mut tasks = JoinSet::new();

        let _ = tasks.spawn(async move {
            assert!(wg_socket_a.initiate_handshake().await.is_ok());
            let _ = wg_socket_a.write(&udp_packet[..]).await;
        });

        let _ = tasks.spawn(async move {
            assert!(wg_socket_b.handshake_response().await.is_ok());
            let mut buf = vec![0u8; 2048];
            let len = wg_socket_b.read(&mut buf).await.unwrap();
            let packet = buf[..len].to_vec();

            assert_eq!(udp_packet_cl, packet);
        });

        tasks.join_all().await;
    }
}
