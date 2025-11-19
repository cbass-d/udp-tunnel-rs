use anyhow::Result;
use boringtun::noise::{Packet, Tunn, TunnResult, errors::WireGuardError};
pub use boringtun::x25519;
use log::{error, info, warn};
use std::{collections::HashMap, io, net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::timeout};

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeState {
    Started,
    Done,
    None,
}

#[derive(thiserror::Error, Debug)]
pub enum WgTransportError {
    #[error("Timeout received")]
    Timeout,
    #[error("Socket not binded")]
    NotBinded,
    #[error("Socket not connected")]
    NotConnected,
    #[error("Handshake has not been completed")]
    NoHandshake,
    #[error("Failed to create Tunn structure")]
    CreateTunnFailed,
    #[error("{0}")]
    Bind(io::Error),
    #[error("{0}")]
    Connect(io::Error),
    #[error("{0}")]
    Send(io::Error),
    #[error("{0}")]
    Recv(io::Error),
    #[error("Invalid size: {0}, expected {1}")]
    InvalidSize(usize, usize),
    #[error("Unexpected Wireguard packet")]
    UnexpectedPacket,
    #[error("{0:?}")]
    WgError(WireGuardError),
    #[error("Unknown peer")]
    UnknownPeer,
}

// WgSocket handles the underlying UDP socket as well as the
// Tunn (boringtun::noise::Tunn) structure in order to create and end-to-end
// connection with Wireguard cryptography/encryption
pub struct WgSocket {
    // boringtun::noise::Tunn structure
    // Handles anything with Wireguard
    tunn: Tunn,

    // Socket address the UDP socket will be binded to
    socketaddr: SocketAddr,

    // Underlying UDP socket for end-to-end connection
    // When value is None socket is not binded yet
    // When value is Some socket is binded
    socket: Option<UdpSocket>,

    // Socket address the peer endpoint the UDP socket will be connected to
    peer_socketaddr: SocketAddr,

    // State of the Wireguard handshake of the Tunn structure
    handshake: HandshakeState,

    // Whether the UDP socket is connected to the peer endpoint
    connected: bool,
}

impl WgSocket {
    // Creates a new WgSocket and Tunn using the specified static private key, index, and peer public
    // static key and peer endpoint socket address
    // The value of socket (UDP socket) is initialized as None as it must be binded using .bind()
    pub fn new(
        static_private: x25519::StaticSecret,
        index: u32,
        socketaddr: SocketAddr,
        peer_static_public: x25519::PublicKey,
        peer_socketaddr: SocketAddr,
    ) -> Result<Self, WgTransportError> {
        let tunn = match Tunn::new(static_private, peer_static_public, None, None, index, None) {
            Ok(tunn) => tunn,
            Err(_) => return Err(WgTransportError::CreateTunnFailed),
        };

        Ok(Self {
            tunn,
            socketaddr,
            socket: None,
            peer_socketaddr,
            handshake: HandshakeState::None,
            connected: false,
        })
    }

    // Binds the underlying UDP socket and makes is usable to connect to the peer endpoint
    // as well as updating the socket value to Some
    pub async fn bind(&mut self) -> Result<(), WgTransportError> {
        if self.socket.is_none() {
            let socket = match UdpSocket::bind(self.socketaddr).await {
                Ok(socket) => socket,
                Err(e) => return Err(WgTransportError::Bind(e)),
            };

            self.socket = Some(socket);
            info!("UDP socket binded to {}", self.socketaddr);
        } else {
            warn!("Attempted to rebind socket");
            return Err(WgTransportError::Bind(io::ErrorKind::Other.into()));
        }

        Ok(())
    }

    // Connects the underlying UDP socket to the peer endpoint if binded, fails otherwise
    pub async fn connect(&mut self) -> Result<(), WgTransportError> {
        if let Some(ref socket) = self.socket {
            socket
                .connect(self.peer_socketaddr)
                .await
                .map_err(WgTransportError::Connect)?;

            info!(
                "Connected to peer: {} -> {}",
                self.socketaddr, self.peer_socketaddr
            );
        } else {
            error!("Connect failed: no binded socket");
            return Err(WgTransportError::NotBinded);
        }

        self.connected = true;
        Ok(())
    }

    // Initiate the Wireguard handshake with the specified peer endpoint using the
    // underlying Tunn structure and UDP socket. Fails if the UDP socket is not binded or connected
    pub async fn initiate_handshake(&mut self) -> Result<(), WgTransportError> {
        if !self.connected {
            error!("Handshake initiation failed: socket not connected");
            return Err(WgTransportError::NotConnected);
        }

        let socket = match self.socket.as_ref() {
            Some(socket) => socket,
            None => {
                error!("Handshake initiation failed: no binded socket");
                return Err(WgTransportError::NotBinded);
            }
        };

        info!("Initiating handshake");
        self.handshake = HandshakeState::Started;

        // Create and send handshake init
        let mut dst = vec![0u8; 2048];
        let handshake_init = match self.tunn.format_handshake_initiation(&mut dst, false) {
            TunnResult::WriteToNetwork(data) => data,
            TunnResult::Err(e) => {
                error!("Wireguard Tunn error");
                return Err(WgTransportError::WgError(e));
            }
            _ => {
                error!("Unexpected Wireguard packet");
                return Err(WgTransportError::UnexpectedPacket);
            }
        };

        socket
            .send(handshake_init)
            .await
            .map_err(WgTransportError::Send)?;

        info!("Handhsake init message sent");

        // Recieve and parse response
        let mut buf = vec![0u8; 2048];
        if let Ok(recv_res) = timeout(Duration::from_secs(10), socket.recv(&mut buf)).await {
            let len = recv_res.map_err(WgTransportError::Recv)?;

            info!("Handshake resp message received");

            let handshake_resp = self.tunn.decapsulate(None, &buf[..len], &mut dst);
            // Create and send keep alive
            let keepalive = match handshake_resp {
                TunnResult::WriteToNetwork(data) => data,
                TunnResult::Err(e) => {
                    error!("Wireguard Tunn error");
                    return Err(WgTransportError::WgError(e));
                }
                _ => {
                    error!("Unexpected Wireguard packet");
                    return Err(WgTransportError::UnexpectedPacket);
                }
            };

            socket
                .send(keepalive)
                .await
                .map_err(WgTransportError::Send)?;

            info!("Keepalive message sent");
        } else {
            return Err(WgTransportError::Timeout);
        }

        self.handshake = HandshakeState::Done;
        Ok(())
    }

    // Respond to the Wireguard handshake initiation message.
    // Fails if the underlyint UDP socket is not binded or connected.
    pub async fn handshake_response(&mut self) -> Result<(), WgTransportError> {
        if !self.connected {
            error!("Handshake initiation failed: socket not connected");
            return Err(WgTransportError::NotConnected);
        }

        let socket = match self.socket.as_ref() {
            Some(socket) => socket,
            None => {
                error!("Handshake initiation failed: no binded socket");
                return Err(WgTransportError::NotBinded);
            }
        };

        self.handshake = HandshakeState::Started;

        // Receive and parse handshake initiation
        let mut buf = vec![0u8; 2048];
        if let Ok(recv_res) = timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
            let len = recv_res.map_err(WgTransportError::Recv)?;

            let handshake_init = &buf[..len];

            info!("Handshake init message received");

            // Create and send handshake response
            let mut dst = [0u8; 2048];
            let handshake_resp = match self.tunn.decapsulate(None, handshake_init, &mut dst) {
                TunnResult::WriteToNetwork(data) => data,
                TunnResult::Err(e) => {
                    error!("Wireguard Tunn error");
                    return Err(WgTransportError::WgError(e));
                }
                _ => {
                    error!("Unexpected Wireguard packet");
                    return Err(WgTransportError::UnexpectedPacket);
                }
            };

            socket
                .send(handshake_resp)
                .await
                .map_err(WgTransportError::Send)?;

            info!("Handshake message sent");

            // Recieve and parse keepalive
            if let Ok(recv_res) = timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
                let len = recv_res.map_err(WgTransportError::Recv)?;

                let _keepalive = &buf[..len];
            } else {
                error!("Timeout from read recieved");
                return Err(WgTransportError::Timeout);
            }
        } else {
            error!("Timeout from read recieved");
            return Err(WgTransportError::Timeout);
        }

        self.handshake = HandshakeState::Done;

        Ok(())
    }

    // Write to the Wireguard peer by using to underlying Tunn structure to
    // encrypt/encapsulate the data and the UDP socket to send it to the peer endpoint.
    // Fails if the Tunn has not performed the necessary Wireguard handshake.
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, WgTransportError> {
        if self.handshake != HandshakeState::Done {
            error!("Write failed: no handshake");
            return Err(WgTransportError::NoHandshake);
        }

        let mut dst = vec![0u8; 2048];
        let enc_data = match self.tunn.encapsulate(data, &mut dst) {
            TunnResult::WriteToNetwork(data) => data,
            TunnResult::Err(e) => {
                error!("Wireguard Tunn error");
                return Err(WgTransportError::WgError(e));
            }
            _ => {
                error!("Unexpected Wireguard packet");
                return Err(WgTransportError::UnexpectedPacket);
            }
        };

        let socket = match self.socket.as_ref() {
            Some(socket) => socket,
            None => {
                error!("Handshake initiation failed: no binded socket");
                return Err(WgTransportError::NotBinded);
            }
        };

        let len = socket
            .send(enc_data)
            .await
            .map_err(WgTransportError::Send)?;

        Ok(len)
    }

    // Read from the Wireguard peer by using to underlying Tunn structure to
    // decryp/decapsulate the data received from the UDP socket connection.
    // Fails if the Tunn has not performed the necessary Wireguard handshake.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, WgTransportError> {
        if self.handshake != HandshakeState::Done {
            error!("Write failed: no handshake");
            return Err(WgTransportError::NoHandshake);
        }

        let socket = match self.socket.as_ref() {
            Some(socket) => socket,
            None => {
                error!("Handshake initiation failed: no binded socket");
                return Err(WgTransportError::NotBinded);
            }
        };

        let len = socket.recv(buf).await.map_err(WgTransportError::Recv)?;

        let mut dst = vec![0u8; 2048];
        let data = match self.tunn.decapsulate(None, &buf[..len], &mut dst) {
            TunnResult::WriteToTunnelV4(data, _src) => data,
            TunnResult::Err(e) => {
                error!("Wireguard Tunn error");
                return Err(WgTransportError::WgError(e));
            }
            _ => {
                error!("Unexpected Wireguard packet");
                return Err(WgTransportError::UnexpectedPacket);
            }
        };

        let out_len = data.len();
        buf[..out_len].copy_from_slice(data);
        Ok(out_len)
    }
}

pub type PeerConnection = (x25519::PublicKey, Tunn);

// A listener that uses a UDP socket to handle one-to-many connections
// that uses a dedictaed Tunn (boringtun::noise::Tunn) for each of the
// connections for an end-to-end connection with Wireguard cryptography/encryption
pub struct WgListener {
    // Socket address the listener is binded to
    socketaddr: SocketAddr,

    // Underlying UDP socket for end-to-end connections
    // When value is None socket is not binded yet
    // When value is Some socket is binded
    socket: Option<UdpSocket>,

    // Hashmap containing the active connected peers.
    // Indexed by the peer endpoint socket address and points
    // to the peer public key and respective Tunn structure
    peers: HashMap<SocketAddr, PeerConnection>,

    // Static secret used to build the needed Tunn structures for
    // the client connections
    static_secret: x25519::StaticSecret,

    // Static public key
    static_pub: x25519::PublicKey,

    // Index used in Wireguard protocol
    index: u32,
}

impl WgListener {
    // Creates a new WgListener using the specified static private key, index, and peer public
    // static key and peer endpoint socket address
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

    // Binds the underlying UDP socket and makes is usable for future use,
    // as well as updating the socket value to Some
    pub async fn bind(&mut self) -> Result<(), WgTransportError> {
        if self.socket.is_none() {
            let socket = UdpSocket::bind(self.socketaddr)
                .await
                .map_err(WgTransportError::Bind)?;

            self.socket = Some(socket);
            info!("UDP socket binded to {}", self.socketaddr);
        } else {
            warn!("Attempted to rebind socket");
        }

        Ok(())
    }

    // Handles and responds to the Wireguard handshake initiation
    // message recieved from an incoming connection. Once handshake succeeds
    // the connection is added as a peer and the corresponding Tunn structure
    // its stored for future use.
    pub async fn handle_handshake_init(
        &mut self,
        handshake_init: &[u8],
        endpoint: SocketAddr,
    ) -> Result<(), WgTransportError> {
        if handshake_init.len() != 148 {
            return Err(WgTransportError::InvalidSize(handshake_init.len(), 148));
        }

        let socket = match self.socket.as_ref() {
            Some(socket) => socket,
            None => {
                error!("Handshake initiation failed: no binded socket");
                return Err(WgTransportError::NotBinded);
            }
        };

        let handshake_init_p = match Tunn::parse_incoming_packet(handshake_init).unwrap() {
            Packet::HandshakeInit(p) => p,
            _ => {
                error!("Unexpect Wireguard packet");
                return Err(WgTransportError::UnexpectedPacket);
            }
        };

        let halfhandshake = match boringtun::noise::handshake::parse_handshake_anon(
            &self.static_secret,
            &self.static_pub,
            &handshake_init_p,
        ) {
            Ok(p) => p,
            Err(_) => {
                error!("Unexpect Wireguard packet");
                return Err(WgTransportError::UnexpectedPacket);
            }
        };

        let peer_static_public = x25519::PublicKey::from(halfhandshake.peer_static_public);

        let mut tunn = match Tunn::new(
            self.static_secret.clone(),
            peer_static_public,
            None,
            None,
            self.index,
            None,
        ) {
            Ok(tunn) => tunn,
            Err(_) => {
                error!("Unexpect Wireguard packet");
                return Err(WgTransportError::CreateTunnFailed);
            }
        };

        let mut dst = vec![0u8; 2048];
        match tunn.decapsulate(None, handshake_init, &mut dst) {
            TunnResult::WriteToNetwork(data) => {
                socket
                    .send_to(data, endpoint)
                    .await
                    .map_err(WgTransportError::Send)?;
            }
            TunnResult::Err(e) => {
                return Err(WgTransportError::WgError(e));
            }
            _ => {
                return Err(WgTransportError::UnexpectedPacket);
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

    // Listen for incoming connections as well as messages. When a message
    // is recieved it checks if the peer is known. If it is known we perform
    // the decryption/decapsulation using the peer's respective Tunn structure.
    // If it is not known, the Wireguard handshake is performed.
    pub async fn incoming(&mut self) -> Result<Option<Vec<u8>>, WgTransportError> {
        let socket = match self.socket.as_ref() {
            Some(socket) => socket,
            None => {
                error!("Listener socket not binded");
                return Err(WgTransportError::NotBinded);
            }
        };

        let mut buf = vec![0u8; 2048];
        let (len, peer) = socket
            .recv_from(&mut buf)
            .await
            .map_err(WgTransportError::Recv)?;

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
                    error!("Wireguard error: {e:?}");
                    return Err(WgTransportError::WgError(e));
                }
                TunnResult::WriteToTunnelV4(data, _src) => {
                    return Ok(Some(data.into()));
                }
                _ => {
                    error!("Unexpect Wireguard packet");
                    return Err(WgTransportError::UnexpectedPacket);
                }
            }
        }

        let handshake_init = &buf[..len];
        self.handle_handshake_init(handshake_init, peer).await?;

        Ok(None)
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
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::max())
            .is_test(true)
            .try_init();
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
