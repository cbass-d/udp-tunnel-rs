pub mod behaviour;
pub mod builder;
pub mod gossip_handler;
pub mod identify_handler;
pub mod kad_handler;

use futures::prelude::*;
use std::{collections::HashMap, time::Duration};

use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm,
    core::ConnectedPoint,
    gossipsub::IdentTopic,
    identity::Keypair,
    kad::{PeerInfo, RecordKey},
    swarm::SwarmEvent,
};
use log::{debug, error, info, warn};
use tokio_util::sync::CancellationToken;

use crate::{
    WgMeshError,
    config::Config,
    mesh::{Mesh, MeshPeer},
    message::Info,
    peer::{
        behaviour::{WgMeshBehaviour, WgMeshEvent},
        kad_handler::KadQueries,
    },
    util::split_peer_id,
};

// Protocol names
const IPFS_KAD_PROTO_NAME: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");
const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/ipfs/id/1.0.0");
const WG_MESH_PROTO_NAME: StreamProtocol = StreamProtocol::new("/wg-mesh-message");

// Application agent
const WG_MESH_AGENT: &str = "wg-mesh/0.0.1";

// Gossipsub topics
const GOSSIPSUB_WG_MESH_CHANNEL: &str = "wg-mesh-channel";

pub struct Peer {
    pub id: PeerId,
    pub peers: HashMap<PeerId, MeshPeer>,
    pub swarm: Swarm<WgMeshBehaviour>,
    keypair: Keypair,
    known_peers: Vec<Multiaddr>,

    // Peer has subscribed to wg-mesh gossipsub topic
    subscribed: bool,

    // Init/intro message containing peer info has been sent to wg-mesh topic
    init_sent: bool,

    // Peer has the role of bootstrap node in the mesh network
    is_bootstrap: bool,

    // Peer can act as an exit node in the mesh network
    is_exit: bool,
    bootstrapped: bool,

    // IDs of important KAD queries
    // * bootstrap
    // * providing agent string
    // * get providers
    kad_queries: KadQueries,
}

impl Peer {
    // Main event loop of the node.
    // Sets the node to listen on the port provided by the CLI.
    // Reads in events from the libp2p Swarm.
    pub async fn run(
        &mut self,
        config: &Config,
        cancel_token: CancellationToken,
    ) -> Result<(), WgMeshError> {
        self.swarm
            .listen_on(
                format!("/ip4/127.0.0.1/udp/{}/quic-v1", config.listen_port)
                    .parse()
                    .map_err(WgMeshError::MultiAddr)?,
            )
            .map_err(|e| WgMeshError::TransportError(e.to_string()))?;

        // Dial known peers passed by CLI and add to Kademlia routing table
        for addr in &self.known_peers {
            if self.swarm.dial(addr.clone()).is_ok() {
                debug!("successully dialed peer {addr}");
                if let Some((peer_id, addr)) = split_peer_id(addr.clone()) {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr);
                }
            } else {
                warn!("failed to dial peer {addr}");
            }
        }

        // Subscribe to the topic/channel where WG-Mesh messages will be sent
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&IdentTopic::new(GOSSIPSUB_WG_MESH_CHANNEL))
        {
            error!("failed to subscribe to {}: {e}", GOSSIPSUB_WG_MESH_CHANNEL);
            return Err(WgMeshError::FailedSubTopic(
                GOSSIPSUB_WG_MESH_CHANNEL.to_string(),
            ));
        } else {
            info!("subscribed to wg mesh channel");
            self.subscribed = true;

            // Send introductory message when joined
            let intro_info = Info {
                is_bootstrap: Some(self.is_bootstrap),
                is_exit: Some(self.is_exit),
            };

            // Convert message to bytes and sendable format
            let info_bytes = serde_json::to_vec(&intro_info).map_err(WgMeshError::SerdeError)?;
            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(
                IdentTopic::new(GOSSIPSUB_WG_MESH_CHANNEL).hash(),
                info_bytes,
            ) {
                error!("failed to publish intro message: {e}");
            } else {
                info!("published intro message");
                self.init_sent = true;
            }
        }

        // Initialize KAD bootstrap process if we know already existing peers
        if !self.known_peers.is_empty() {
            if let Ok(qid) = self.swarm.behaviour_mut().kademlia.bootstrap() {
                info!("kademlia bootstrap started");
                self.kad_queries.bootsrap_id = Some(qid);
            } else {
                warn!("initial kademlia bootstrap failed");
            }
        }

        // Start providing the agent version string this
        // will help identify the nodes that are able to process wg mesh requests
        let key = RecordKey::new(&WG_MESH_AGENT);
        if self.is_bootstrap {
            if let Ok(qid) = self
                .swarm
                .behaviour_mut()
                .kademlia
                .start_providing(key.clone())
            {
                self.kad_queries.providing_agent_id = Some(qid);
                debug!("kademlia attempting to providing {:?}", key);
            }
        }

        let mut interval = tokio::time::interval(Duration::from_secs(10));
        interval.reset();

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    debug!("Stopping listening...");
                    break;
                },
                Some(event) = self.swarm.next() => {
                    match event {
                        SwarmEvent::Dialing { peer_id, ..} => {
                            debug!("dialing peer {:?}", peer_id);
                        },
                        SwarmEvent::NewListenAddr { address, .. } => {
                            let local_p2p_addr = address.clone()
                                    .with_p2p(*self.swarm.local_peer_id()).unwrap();
                            info!("Listening on p2p address {:?}", local_p2p_addr);
                        },
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, connection_id, .. } => {
                            info!("new peer {} from {:?}", peer_id, endpoint);
                            let peer_addr = match endpoint {
                                ConnectedPoint::Dialer { address, ..} => address,
                                ConnectedPoint::Listener { send_back_addr, ..} => send_back_addr,
                            };
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, peer_addr);

                            // Once we have at least one connection, the bootstrap node also
                            // starts the kad bootstrapping process
                            if self.is_bootstrap && !self.bootstrapped {
                                match self.swarm.behaviour_mut().kademlia.bootstrap() {
                                    Ok(qid) => {
                                        info!("kademlia bootstrap started");
                                        self.kad_queries.bootsrap_id = Some(qid);
                                    },
                                    Err(e) => {
                                        warn!("initial kademlia bootstrap failed: {e}");
                                    }
                                }
                            }
                        },
                        SwarmEvent::ConnectionClosed { peer_id, endpoint, cause, connection_id, .. } => {
                            info!("connection closed peer {} ({:?}) cause: {:?}", peer_id, endpoint, cause);

                            self.remove_peer(peer_id);
                        },
                        SwarmEvent::IncomingConnectionError { peer_id, error, ..} => {
                                error!("incoming connection failed, peer {:?}: {error}", peer_id);
                        },
                        SwarmEvent::Behaviour(WgMeshEvent::Identify(event)) => {
                            identify_handler::handle_event(self, event)?;
                        },
                        SwarmEvent::Behaviour(WgMeshEvent::Kademlia(event)) => {
                            kad_handler::handle_event(self, event)?;
                        },
                        SwarmEvent::Behaviour(WgMeshEvent::Gossipsub(event)) => {
                            gossip_handler::handle_event(self, event)?;
                        },
                        other => {
                            info!("new event: {:?}", other);
                        }
                    }
                },
                _ = interval.tick() => {
                    debug!("node mode: {}", self.swarm.behaviour().kademlia.mode());

                    self.on_tick()?;

                }
            }
        }

        // Clean up on exit
        self.clean_up();

        Ok(())
    }

    fn attempt_topic_subscription(&mut self, topic: &str) -> Result<(), WgMeshError> {
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&IdentTopic::new(topic))
        {
            error!("failed to subscribe to {}: {e}", topic);
            return Err(WgMeshError::FailedSubTopic(
                GOSSIPSUB_WG_MESH_CHANNEL.to_string(),
            ));
        }

        Ok(())
    }

    // Send introductory message when joining gossipsub wg-mesh topic
    fn attempt_intro_message(&mut self) -> Result<(), WgMeshError> {
        let intro_info = Info {
            is_bootstrap: Some(self.is_bootstrap),
            is_exit: Some(self.is_exit),
        };
        let info_bytes = serde_json::to_vec(&intro_info).map_err(WgMeshError::SerdeError)?;
        if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(
            IdentTopic::new(GOSSIPSUB_WG_MESH_CHANNEL).hash(),
            info_bytes,
        ) {
            return Err(WgMeshError::FailedInitMessage(e.to_string()));
        }

        Ok(())
    }

    fn on_tick(&mut self) -> Result<(), WgMeshError> {
        // Re-attempt to subscribe gossipsub if needed
        if !self.subscribed {
            if let Ok(_) = self.attempt_topic_subscription(GOSSIPSUB_WG_MESH_CHANNEL) {
                debug!("subscribed to wg-mesh topic");
                self.subscribed = true;
            }
        }

        // Re-attempt to send gossipsub
        if self.subscribed && !self.init_sent {
            if let Ok(_) = self.attempt_intro_message() {
                info!("published intro message");
                self.init_sent = true;
            }
        }

        Ok(())
    }

    fn clean_up(&mut self) {
        debug!("cleaning up...");

        // Unsubscribe from gossipsub topics
        self.swarm
            .behaviour_mut()
            .gossipsub
            .unsubscribe(&IdentTopic::new(GOSSIPSUB_WG_MESH_CHANNEL));
    }

    pub fn build_mesh(&self, peers: Vec<PeerInfo>) {
        let mesh = Mesh::new(self.id, peers);
        debug!("{}", mesh);
    }

    fn add_peer(
        &mut self,
        peer_id: PeerId,
        listen_addrs: Vec<Multiaddr>,
        pub_key: libp2p_identity::PublicKey,
    ) {
        let mesh_peer = MeshPeer::new(peer_id, listen_addrs, pub_key);
        self.peers.insert(peer_id, mesh_peer);
        info!("added new peer {} to list of peers", peer_id);
    }

    fn remove_peer(&mut self, peer_id: PeerId) {
        self.peers.remove(&peer_id);
        debug!("removed peer {} from list of peers", peer_id);
    }
}
