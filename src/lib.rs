use libp2p::{Multiaddr, PeerId};
use std::{io, net::SocketAddr};

pub mod config;
pub mod key;
pub mod mesh;
pub mod message;
pub mod peer;
pub mod util;
pub mod wg;

pub type KnownPeer = (PeerId, Multiaddr);

#[derive(Debug, thiserror::Error)]
pub enum WgMeshError {
    #[error("{0}")]
    FailedToLoadConf(String),
    #[error("{0}")]
    FailedToStoreConf(String),
    #[error("{0}")]
    Bind(io::Error),
    #[error("{0}")]
    SendTo(io::Error),
    #[error("{0}")]
    Io(io::Error),
    #[error("{0}")]
    MultiAddr(libp2p::multiaddr::Error),
    #[error("{0}")]
    TransportError(String),
    #[error("Tunn creation failed")]
    TunnCreateFailed,
    #[error("Peer with duplicate endpoint: {0}")]
    DuplicateEndpoint(SocketAddr),
    #[error("No peer with such endpoint")]
    NoSuchPeer,
    #[error("mpsc send failed")]
    SendError,
    #[error("{0}")]
    InvalidKeyFile(String),
    #[error("{0}")]
    SwarmBuild(String),
    #[error("At least one peer node needed")]
    NoPeerNodes,
    #[error("No private key set")]
    NoPrivateKey,
    #[error("Failed to subscribe: {0}")]
    FailedSubTopic(String),
    #[error("Failed to send init message: {0}")]
    FailedInitMessage(String),
    #[error("Gossipsub init: {0}")]
    GossipsubInit(String),
    #[error("{0}")]
    DecodeError(String),
    #[error("{0}")]
    SerdeError(serde_json::Error),
    //#[error("Kademlia init: {0}")]
    //Kademlia(String),
    //#[error("Identify protocol init: {0}")]
    //IdentifyInit(String),
}
