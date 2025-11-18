use anyhow::{Result, anyhow};
use boringtun::noise::{Packet, Tunn, TunnResult};
pub use boringtun::x25519;
use log::{error, info, warn};
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::timeout};

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
    ) -> Result<Self> {
        let tunn = Tunn::new(static_private, peer_static_public, None, None, index, None).unwrap();

        Ok(Self {
            tunn,
            socketaddr,
            socket: None,
            peer_socketaddr,
            handshake: HandshakeState::None,
        })
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

    // Perform WG handshake as initiator
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
        let handshake_init = if let TunnResult::WriteToNetwork(data) =
            self.tunn.format_handshake_initiation(&mut dst, false)
        {
            data
        } else {
            unreachable!();
        };

        socket.send(handshake_init).await?;
        info!("Handhsake init message sent");

        // Recieve and parse response
        let mut buf = vec![0u8; 2048];
        if let Ok(Ok(len)) = timeout(Duration::from_secs(10), socket.recv(&mut buf)).await {
            info!("Handshake resp message received");

            let handshake_resp = self.tunn.decapsulate(None, &buf[..len], &mut dst);
            // Create and send keep alive
            let keepalive = if let TunnResult::WriteToNetwork(data) = handshake_resp {
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

    // Perform WG handshake as responder
    pub async fn handshake_response(&mut self) -> Result<()> {
        if self.socket.is_none() {
            error!("Handshake response failed: no binded socket");
            return Err(WgSocketError::NotBinded.into());
        }
        let socket = self.socket.as_ref().unwrap();
        self.handshake = HandshakeState::Started;

        // Receive and parse handshake initiation
        let mut buf = vec![0u8; 2048];
        if let Ok(Ok(len)) = timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
            info!("Handshake init message received");

            let handshake_init = &buf[..len];

            // Create and send handshake response
            let mut dst = [0u8; 2048];
            let handshake_resp = if let TunnResult::WriteToNetwork(data) =
                self.tunn.decapsulate(None, handshake_init, &mut dst)
            {
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

    // Write to WG Peer
    pub async fn write(&mut self, data: &[u8]) -> Result<usize> {
        if self.handshake != HandshakeState::Done {
            error!("Write failed: no handshake");
            return Err(WgSocketError::NoHandshake.into());
        }

        let mut dst = vec![0u8; 2048];
        let enc_data =
            if let TunnResult::WriteToNetwork(data) = self.tunn.encapsulate(data, &mut dst) {
                data
            } else {
                unreachable!();
            };

        let socket = self.socket.as_ref().unwrap();
        let len = socket.send(enc_data).await?;

        Ok(len)
    }

    // Read from WG Peer
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.handshake != HandshakeState::Done {
            error!("Write failed: no handshake");
            return Err(WgSocketError::NoHandshake.into());
        }

        let socket = self.socket.as_ref().unwrap();
        let len = socket.recv(buf).await?;
        let mut dst = vec![0u8; 2048];
        let data = if let TunnResult::WriteToTunnelV4(data, _src) =
            self.tunn.decapsulate(None, &buf[..len], &mut dst)
        {
            data
        } else {
            unreachable!();
        };

        let out_len = data.len();
        buf[..out_len].copy_from_slice(data);
        Ok(out_len)
    }

    // Set static private key
}

pub type PeerConnection = (x25519::PublicKey, Tunn);

pub struct WgListener {
    socketaddr: SocketAddr,
    socket: Option<UdpSocket>,
    peers: HashMap<SocketAddr, PeerConnection>,
    static_secret: x25519::StaticSecret,
    static_pub: x25519::PublicKey,
    index: u32,
}

impl WgListener {
    pub fn new(
        static_secret: x25519::StaticSecret,
        static_pub: x25519::PublicKey,
        socketaddr: SocketAddr,
        index: u32,
    ) -> Self {
        Self {
            socketaddr,
            socket: None,
            peers: HashMap::new(),
            static_secret,
            static_pub,
            index,
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

    // As a listener we will only be acting as the responder
    // during the WG handshake
    pub async fn handle_handshake_init(
        &mut self,
        handshake_init: &[u8],
        endpoint: SocketAddr,
    ) -> Result<()> {
        if handshake_init.len() != 148 {
            return Err(anyhow!("Invalid handshake init size"));
        }

        if self.socket.is_none() {
            error!("Handshake initiation failed: no binded socket");
            return Err(WgSocketError::NotBinded.into());
        }
        let socket = self.socket.as_ref().unwrap();

        let handshake_init_p = if let Packet::HandshakeInit(p) =
            Tunn::parse_incoming_packet(handshake_init).unwrap()
        {
            p
        } else {
            return Err(anyhow!("unexpected wireguard packet type"));
        };
        let halfhandshake = boringtun::noise::handshake::parse_handshake_anon(
            &self.static_secret,
            &self.static_pub,
            &handshake_init_p,
        )
        .unwrap();

        let peer_static_public = x25519::PublicKey::from(halfhandshake.peer_static_public);

        let mut tunn = Tunn::new(
            self.static_secret.clone(),
            peer_static_public,
            None,
            None,
            self.index,
            None,
        )
        .unwrap();

        let mut dst = vec![0u8; 2048];
        match tunn.decapsulate(None, handshake_init, &mut dst) {
            TunnResult::WriteToNetwork(data) => {
                socket.send_to(data, endpoint).await?;
            }
            TunnResult::Err(e) => {
                println!("{e:?}");
                return Err(anyhow!("{e:?}"));
            }
            _ => {
                return Err(anyhow!("unexpted tunn result"));
            }
        }
        //// Recieve and parse keepalive
        //let mut buf = vec![0u8; 2048];
        //match timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
        //    Ok(Ok(len)) => {
        //        info!("Keepalive message received");
        //        let res = tunn.decapsulate(None, &buf[..len], &mut dst);
        //    }
        //    Err(e) => {
        //        return Err(e.into());
        //    }
        //    _ => {
        //        return Err(anyhow!("Recieved failed"));
        //    }
        //}

        let peer_connection: PeerConnection = (peer_static_public, tunn);
        self.peers.insert(endpoint, peer_connection);

        Ok(())
    }

    // Listen for incoming connections and messages
    // * If peer not known, perform WG handshake
    // * If known, decapsulate and pass back data
    pub async fn incoming(&mut self) -> Result<Option<Vec<u8>>> {
        if self.socket.is_none() {
            error!("Accept failed: no binded socket");
            return Err(WgSocketError::NotBinded.into());
        }
        let socket = self.socket.as_ref().unwrap();

        let mut buf = vec![0u8; 2048];
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                if self.peers.contains_key(&peer) {
                    let (_pub_key, tunn) = self.peers.get_mut(&peer).unwrap();

                    let mut dst = vec![0u8; 2048];
                    match tunn.decapsulate(None, &buf[..len], &mut dst) {
                        TunnResult::Done => {
                            return Ok(None);
                        }
                        TunnResult::WriteToNetwork(data) => {
                            return Ok(Some(data.into()));
                        }
                        TunnResult::Err(e) => {
                            return Err(anyhow!("{e:?}"));
                        }
                        TunnResult::WriteToTunnelV4(data, _src) => {
                            return Ok(Some(data.into()));
                        }
                        _ => {
                            return Err(anyhow!("Unexpted message"));
                        }
                    }
                }

                let handshake_init = &buf[..len];
                self.handle_handshake_init(handshake_init, peer).await?;

                Ok(None)
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use boringtun::x25519;
    use rand_core::{OsRng, RngCore};
    use tokio::task::JoinSet;

    use crate::{WgListener, WgSocket};

    async fn create_socket_pair() -> (WgSocket, WgSocket) {
        let addr_a = SocketAddr::from(([127, 0, 0, 1], 6001));
        let addr_b = SocketAddr::from(([127, 0, 0, 1], 6002));

        let secret_a = x25519::StaticSecret::random_from_rng(OsRng);
        let public_a = x25519::PublicKey::from(&secret_a);
        let idx_a = OsRng.next_u32();

        let secret_b = x25519::StaticSecret::random_from_rng(OsRng);
        let public_b = x25519::PublicKey::from(&secret_b);
        let idx_b = OsRng.next_u32();

        let mut wg_socket_a = WgSocket::new(secret_a, idx_a, addr_a, public_b, addr_b).unwrap();
        let mut wg_socket_b = WgSocket::new(secret_b, idx_b, addr_b, public_a, addr_a).unwrap();

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

    #[tokio::test]
    async fn listener_test() {
        let listener_priv = x25519::StaticSecret::random_from_rng(OsRng);
        let listener_pub = x25519::PublicKey::from(&listener_priv);
        let listener_idx = OsRng.next_u32();

        let client_priv = x25519::StaticSecret::random_from_rng(OsRng);
        let _client_pub = x25519::PublicKey::from(&client_priv);
        let client_idx = OsRng.next_u32();

        let listener_sockaddr = SocketAddr::from(([127, 0, 0, 1], 6003));
        let client_sockaddr = SocketAddr::from(([127, 0, 0, 1], 6004));

        let udp_packet = create_udp_packet();
        let packet_clone = udp_packet.clone();

        let mut tasks = JoinSet::new();
        let _ = tasks.spawn(async move {
            let mut wg_listener =
                WgListener::new(listener_priv, listener_pub, listener_sockaddr, listener_idx);
            let _ = wg_listener.bind().await;

            // First call to incoming handles the handshake init
            assert!(wg_listener.incoming().await.is_ok());

            // Second call handles the keep-alive sent after handshake
            assert!(wg_listener.incoming().await.is_ok());

            // Third call recevies the actual first packet of data
            assert_eq!(wg_listener.incoming().await.unwrap(), Some(packet_clone));
        });

        let _ = tasks.spawn(async move {
            let mut wg_socket = WgSocket::new(
                client_priv,
                client_idx,
                client_sockaddr,
                listener_pub,
                listener_sockaddr,
            )
            .unwrap();

            wg_socket.bind().await.unwrap();
            wg_socket.connect().await.unwrap();
            wg_socket.initiate_handshake().await.unwrap();
            wg_socket.write(&udp_packet).await.unwrap();
        });

        let _ = tasks.join_all().await;
    }
}
