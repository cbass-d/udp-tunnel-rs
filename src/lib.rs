use std::{io, net::SocketAddr};

use libp2p::{Multiaddr, PeerId};

pub mod behaviour;
pub mod config;
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
    #[error("Failed to subscribe: {0}")]
    FailedSubTopic(String),
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

//pub async fn run_node(
//    config: Arc<Config>,
//    keypair: Keypair,
//    cancel_token: CancellationToken,
//) -> Result<(), WgMeshError> {
//    // Non-bootstrap nodes need at least one peer node
//    // in order to join the network
//    if !config.bootstrap && config.known_peers.is_none() {
//        return Err(WgMeshError::NoPeerNodes.into());
//    }
//
//    let known_peers = if let Some(known_peers) = &config.known_peers {
//        let peers = read_peer_list(known_peers);
//        info!("Known peers: {:?}", peers);
//        Some(peers)
//    } else {
//        None
//    };
//
//    //let (mut node, mut swarm) = Node::build(&config)?;
//    //node.add_known(&mut swarm, known_peers);
//
//    //{
//    //    let token = cancel_token.clone();
//    //    tokio::spawn(async move { node.run(swarm, &config.clone(), token).await });
//    //    debug!("listen task started");
//    //}
//
//    loop {
//        tokio::select! {
//            _ = cancel_token.cancelled() => {
//                 break;
//             },
//        }
//    }
//
//    Ok(())
//}
