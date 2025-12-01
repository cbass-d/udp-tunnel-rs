use futures::prelude::*;
use libp2p_identity::PublicKey;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::Duration,
};

use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
    core::ConnectedPoint,
    gossipsub::{
        Behaviour as Gossipsub, ConfigBuilder as GossipConfigBuilder, Event as GossipsubEvent,
        IdentTopic, MessageAuthenticity,
    },
    identify::{self, Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent},
    identity::Keypair,
    kad::{
        self, Behaviour as Kademlia, Config as KadConfig, GetRecordOk, InboundRequest, Mode,
        PeerInfo, ProgressStep, QueryId, QueryResult, RecordKey, store::MemoryStore,
    },
    swarm::{ConnectionId, SwarmEvent},
};
use log::{debug, error, info, warn};
use tokio_util::sync::CancellationToken;

use crate::{
    WgMeshError,
    behaviour::{Behaviour, BehaviourEvent},
    config::Config,
    mesh::{Mesh, MeshPeer},
    message::{Info, WgMeshMessage},
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
    peers: HashMap<PeerId, MeshPeer>,
    swarm: Swarm<Behaviour>,
    subscribed: bool,
    init_sent: bool,
    is_bootstrap: bool,
    bootstrapped: bool,
    init_bootsrap_id: Option<QueryId>,
    providing_agent_id: Option<QueryId>,
    get_providers_id: Option<QueryId>,
    open_connections: HashSet<ConnectionId>,
}

impl Peer {
    pub fn build(config: &Config, keypair: Keypair) -> Result<Self, WgMeshError> {
        let peer_id = PeerId::from_public_key(&keypair.public());

        let swarm = {
            let identify = {
                let cfg = IdentifyConfig::new(IPFS_PROTO_NAME.to_string(), keypair.public())
                    .with_agent_version(WG_MESH_AGENT.to_string());

                Identify::new(cfg)
            };

            let kademlia: Kademlia<MemoryStore> = {
                let mut cfg = KadConfig::new(IPFS_KAD_PROTO_NAME);
                cfg.set_query_timeout(Duration::from_secs(60));
                cfg.set_periodic_bootstrap_interval(Some(Duration::from_secs(200)));

                let store = MemoryStore::new(peer_id);
                Kademlia::with_config(peer_id, store, cfg)
            };

            let gossipsub = {
                //let message_id_fn = |message: &GossipsubMessage| {
                //    let mut hash = DefaultHasher::new();
                //    message.data.hash(&mut hash);
                //    GossipsubMessageId::from(hash.finish().to_string())
                //};

                let config = GossipConfigBuilder::default()
                    .mesh_outbound_min(1)
                    .mesh_n_low(1)
                    .flood_publish(false)
                    .build()
                    .map_err(|e| WgMeshError::GossipsubInit(e.to_string()))?;

                Gossipsub::new(MessageAuthenticity::Signed(keypair.clone()), config)
                    .map_err(|e| WgMeshError::GossipsubInit(e.to_string()))?
            };

            //let request_response = {
            //    let cfg = RRConfig::default();
            //    RequestResponse::new([(WG_MESH_PROTO_NAME, ProtocolSupport::Full)], cfg)
            //};

            let behaviour = Behaviour {
                identify,
                //request_response,
                gossipsub,
                kademlia,
            };

            let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
                .with_tokio()
                .with_quic()
                .with_behaviour(|_key| behaviour)
                .map_err(|e| WgMeshError::SwarmBuild(e.to_string()))?
                .build();

            swarm
        };

        // If the node is the boostrap node (the node that a new peer joining
        // must know) we set the mode as server
        if config.is_bootstrap {
            info!("bootstrap node PeerID is: {}", peer_id);
        }

        Ok(Self {
            id: peer_id,
            peers: HashMap::new(),
            swarm,
            subscribed: false,
            init_sent: false,
            is_bootstrap: config.is_bootstrap,
            bootstrapped: false,
            init_bootsrap_id: None,
            providing_agent_id: None,
            get_providers_id: None,
            open_connections: HashSet::new(),
        })
    }

    // Main event loop of the node.
    // Sets the node to listen on the port provided by the CLI.
    // Reads in events from the libp2p Swarm.
    pub async fn run(
        &mut self,
        config: &Config,
        known_peers: Vec<Multiaddr>,
        cancel_token: CancellationToken,
    ) -> Result<(), WgMeshError> {
        self.swarm
            .listen_on(
                format!("/ip4/127.0.0.1/udp/{}/quic-v1", config.listen_port)
                    .parse()
                    .map_err(WgMeshError::MultiAddr)?,
            )
            .map_err(|e| WgMeshError::TransportError(e.to_string()))?;

        // Dial known peers passed by CLI and add to Kademlia addresses
        for addr in &known_peers {
            if self.swarm.dial(addr.clone()).is_ok() {
                debug!("successully dialed peer {addr}");
            } else {
                warn!("failed to dial peer {addr}");
            }

            if let Some((peer_id, addr)) = split_peer_id(addr.clone()) {
                self.swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, addr);
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

            // Send introductory message when joining
            let intro = format!("hello from peer {}", self.id);
            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(
                IdentTopic::new(GOSSIPSUB_WG_MESH_CHANNEL).hash(),
                intro.into_bytes(),
            ) {
                error!("failed to publish intro message: {e}");
            } else {
                info!("published intro message");
                self.init_sent = true;
            }
        }

        if !self.is_bootstrap || !known_peers.is_empty() {
            if let Ok(qid) = self.swarm.behaviour_mut().kademlia.bootstrap() {
                info!("kademlia bootstrap started");
                self.init_bootsrap_id = Some(qid);
            } else {
                warn!("initial kademlia bootstrap failed");
            }
        }

        let key = RecordKey::new(&WG_MESH_AGENT);

        // Start providing the agent version string
        // this will help identify the nodes that are able
        // to process wg mesh requests
        if self.is_bootstrap {
            if let Ok(query_id) = self
                .swarm
                .behaviour_mut()
                .kademlia
                .start_providing(key.clone())
            {
                self.providing_agent_id = Some(query_id);
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
                            self.open_connections.insert(connection_id);
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, peer_addr);

                            if self.is_bootstrap && !self.bootstrapped {
                                match self.swarm.behaviour_mut().kademlia.bootstrap() {
                                    Ok(qid) => {
                                        info!("kademlia bootstrap started");
                                        self.init_bootsrap_id = Some(qid);
                                    },
                                    Err(e) => {
                                        warn!("initial kademlia bootstrap failed: {e}");
                                    }
                                }
                            }
                        },
                        SwarmEvent::ConnectionClosed { peer_id, endpoint, cause, connection_id, .. } => {
                            info!("connection closed peer {} ({:?}) cause: {:?}", peer_id, endpoint, cause);

                            self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);

                            info!("removed peer {peer_id} from routing table");

                            self.remove_peer(peer_id);
                            self.open_connections.remove(&connection_id);
                        },
                        SwarmEvent::IncomingConnectionError { peer_id, error, ..} => {
                                error!("incoming connection failed, peer {:?}: {error}", peer_id);
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::Identify(event)) => {
                            self.handle_identify_event(event);
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::Kademlia(event)) => {
                            self.handle_kad_event(event);
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(event)) => {
                            self.handle_gossipsub_event(event);
                        },
                        other => {
                            info!("new event: {:?}", other);
                        }
                    }
                },
                _ = interval.tick() => {
                    debug!("node mode: {}", self.swarm.behaviour().kademlia.mode());


                    // Preiodically get other providers of the mesh agent string
                    let key = RecordKey::new(&WG_MESH_AGENT);
                    if self.get_providers_id.is_none() {
                        let qid = self.swarm.behaviour_mut().kademlia.get_providers(key);
                        self.get_providers_id = Some(qid);
                    }

                    if !self.subscribed {
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
                        }
                    }

                    if self.subscribed && !self.init_sent {
                        // Send introductory message when joining
                        let intro_info = Info {
                            is_bootstrap: Some(self.is_bootstrap),
                        };

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
                }
            }
        }

        // Clean up on exit
        self.clean_up();

        Ok(())
    }

    fn clean_up(&mut self) {
        debug!("cleaning up...");

        // Unsubscribe from gossipsub topics
        self.swarm
            .behaviour_mut()
            .gossipsub
            .unsubscribe(&IdentTopic::new(GOSSIPSUB_WG_MESH_CHANNEL));

        // Close any open connections
        for connection_id in &self.open_connections {
            debug!("closing connection {:?}", connection_id);
            self.swarm.close_connection(*connection_id);
        }
    }

    pub fn build_mesh(&self, peers: Vec<PeerInfo>) {
        let mesh = Mesh::new(self.id, peers);
        debug!("{}", mesh);
    }

    pub fn handle_gossipsub_event(&mut self, event: GossipsubEvent) {
        match event {
            GossipsubEvent::Message { .. } => {
                if let Ok(wg_mesh_message) = WgMeshMessage::try_from(event) {
                    info!("message recieved: {:?}", wg_mesh_message);
                }
            }
            GossipsubEvent::Subscribed { peer_id, topic } => {
                if peer_id == self.id {
                    info!("Successfully subscribed to {topic}");
                }
            }
            other => {
                debug!("gossipsub event: {:?}", other);
            }
        }
    }

    pub fn handle_identify_event(&mut self, event: identify::Event) {
        match event {
            IdentifyEvent::Received { peer_id, info, .. } => {
                info!("identify recv event {:?}", info);

                if info.agent_version == WG_MESH_AGENT && !self.peers.contains_key(&peer_id) {
                    let mut good_addrs = vec![];
                    for addr in info.listen_addrs.into_iter() {
                        if self.swarm.dial(addr.clone()).is_ok() {
                            info!("dialed peer {addr} from identify recv");
                            good_addrs.push(addr);
                        } else {
                            warn!("failed to dial peer {addr} from identify recv");
                        }
                    }

                    if !good_addrs.is_empty() {
                        // Add wg mesh peer
                        self.add_peer(peer_id, good_addrs, info.public_key);
                    }
                }
            }

            IdentifyEvent::Sent { peer_id, .. } => {
                info!("identify sent event to {peer_id}");
            }
            IdentifyEvent::Pushed { peer_id, info, .. } => {
                info!("identify pushed event to {peer_id} {:?}", info);
            }
            IdentifyEvent::Error { peer_id, error, .. } => match error {
                libp2p::swarm::StreamUpgradeError::Timeout => {
                    self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
                }
                _ => {
                    debug!("identify error: {error}");
                }
            },
        }
    }

    pub fn handle_kad_event(&mut self, event: kad::Event) {
        match event {
            kad::Event::InboundRequest { request } => {
                self.handle_inbound_req(request);
            }
            kad::Event::OutboundQueryProgressed {
                result, id, step, ..
            } => {
                self.handle_query_result(result, id, step);
            }
            kad::Event::RoutingUpdated {
                peer, addresses, ..
            } => {
                info!("route updated for {peer}: {:?}", addresses);
                //self.swarm
                //    .behaviour_mut()
                //    .kademlia
                //    .get_closest_peers(self.id);
                //let _ = self.swarm.dial(peer);
            }
            kad::Event::RoutablePeer { peer, address, .. } => {
                info!("peer {peer} {:?} routable", address);
            }
            kad::Event::PendingRoutablePeer { peer, address, .. } => {
                info!("peer {peer} {:?} pending routable", address);
            }
            kad::Event::ModeChanged { new_mode } => {
                info!("node mode changed to {new_mode}");
            }
            other => {
                debug!("some other kad event: {:?}", other);
            }
        }
    }

    pub fn handle_inbound_req(&self, request: InboundRequest) {
        match request {
            InboundRequest::FindNode { num_closer_peers } => {}
            InboundRequest::GetProvider {
                num_closer_peers,
                num_provider_peers,
            } => {}
            InboundRequest::GetRecord {
                num_closer_peers,
                present_locally,
            } => {}
            InboundRequest::AddProvider { record } => {}
            InboundRequest::PutRecord {
                source,
                connection,
                record,
            } => {}
        }
    }

    pub fn handle_query_result(&mut self, result: QueryResult, id: QueryId, step: ProgressStep) {
        match result {
            QueryResult::Bootstrap(Ok(res)) => {
                if let Some(query_id) = self.init_bootsrap_id {
                    if id == query_id {
                        if step.last {
                            self.init_bootsrap_id = None;
                            self.bootstrapped = true;

                            info!("kademlia bootstrapped");

                            // Once the bootstrap nodes are connected to other
                            // bootstrap nodes we can set them to server mode
                            if self.is_bootstrap {
                                self.swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .set_mode(Some(Mode::Server));
                            }

                            // Get other providers of the agent string to
                            // get info about mesh

                            let key = RecordKey::new(&WG_MESH_AGENT);
                            let qid = self.swarm.behaviour_mut().kademlia.get_providers(key);

                            self.get_providers_id = Some(qid);
                        } else {
                            debug!(
                                "kademlia bootstrapping peer {}, remaining {}",
                                res.peer, res.num_remaining
                            )
                        }
                    }
                }
            }
            QueryResult::Bootstrap(Err(e)) => {
                warn!("failed to bootstrap error: {e}");
                self.init_bootsrap_id = None;
            }
            QueryResult::GetClosestPeers(Ok(closest_res)) => {
                let key = PeerId::from_bytes(&closest_res.key);
                let peers = closest_res.peers;

                info!("closest peers for key {:?}: {:?}", key, peers);
                //self.build_mesh(peers.peers);
            }
            QueryResult::GetClosestPeers(Err(e)) => {
                warn!("get closest peers error: {e}");
            }
            QueryResult::GetProviders(Ok(providers)) => {
                if let Some(qid) = self.get_providers_id {
                    if id == qid {
                        match providers {
                            kad::GetProvidersOk::FoundProviders { key, providers } => {
                                let key = String::from_utf8(key.to_vec());
                                info!("found providers for {:?}:", key);
                                for peer in &providers {
                                    info!("- {peer}");
                                    // Get other possible/peers providers
                                    self.swarm.behaviour_mut().kademlia.get_closest_peers(*peer);
                                }
                                self.get_providers_id = None;
                            }
                            kad::GetProvidersOk::FinishedWithNoAdditionalRecord {
                                closest_peers,
                            } => {
                                info!("get proivders closest_peers: {:?}", closest_peers);
                                for peer in &closest_peers {
                                    info!("- {peer}");
                                    // Get other possible/peers providers
                                    self.swarm.behaviour_mut().kademlia.get_closest_peers(*peer);
                                }
                            }
                        }
                    }
                }
            }
            QueryResult::GetProviders(Err(e)) => {
                if let Some(qid) = self.get_providers_id {
                    if id == qid {
                        self.get_providers_id = None;
                        error!("falied to get providers for wg mesh agent string: {e}");
                    }
                }
            }
            QueryResult::StartProviding(Ok(_)) => {
                if let Some(qid) = self.providing_agent_id {
                    if id == qid && step.last {
                        self.providing_agent_id = None;
                        debug!("node providing wg mesh agent string");
                    }
                }
            }
            QueryResult::StartProviding(Err(e)) => {
                warn!("start providing error: {e}");

                if let Some(qid) = self.providing_agent_id {
                    if id == qid {
                        error!("failed to provide wg agent string");
                        self.providing_agent_id = None;
                    }
                }
            }
            QueryResult::RepublishRecord(_) => {
                debug!("handling republish record result");
            }
            QueryResult::GetRecord(Ok(record_res)) => {
                match record_res {
                    GetRecordOk::FoundRecord(record) => {
                        info!("found record {:?} at {:?}", record.record, record.peer);
                    }
                    _ => {
                        debug!("get record finished with no additional records");
                    }
                }
                debug!("get record result");
            }
            QueryResult::GetRecord(Err(e)) => {
                warn!("get record error: {e}");
            }
            QueryResult::PutRecord(Ok(res)) => {
                let key = String::from_utf8(res.key.to_vec());
                debug!("put record result: {:?}", key);
            }
            QueryResult::PutRecord(Err(e)) => {
                debug!("put record error: {e}");
            }
            QueryResult::RepublishProvider(_) => {
                debug!("handling republish provider result");
            }
            other => {
                debug!("some other query result: {:?}", other);
            }
        }
    }

    fn add_peer(&mut self, peer_id: PeerId, listen_addrs: Vec<Multiaddr>, pub_key: PublicKey) {
        let mesh_peer = MeshPeer::new(peer_id, listen_addrs, pub_key);
        self.peers.insert(peer_id, mesh_peer);
        info!("added new peer {} to list of peers", peer_id);
    }

    fn remove_peer(&mut self, peer_id: PeerId) {
        self.peers.remove(&peer_id);
        debug!("removed peer {} from list of peers", peer_id);
    }

    pub async fn connect(&mut self, peer_endpoint: SocketAddr) -> Result<(), WgMeshError> {
        Ok(())
    }
}

mod test {
    use libp2p::{
        PeerId, Swarm, identify,
        kad::{self, store::MemoryStore},
    };
    use libp2p_identity::Keypair;

    use crate::{config::Config, peer::Peer};

    // Each peer has the other peer as a known peer
    // at build
    //fn create_peer_paer() -> (Peer, Peer) {
    //    let keypair_a = Keypair::generate_ed25519();
    //    let keypair_b = Keypair::generate_ed25519();

    //    let peer_id_a = PeerId::from_public_key(keypair_a.public());
    //    let peer_id_b = PeerId::from_public_key(keypair_b.public());

    //    let port_a = 6000;
    //    let port_b = 6001;

    //    let multiaddr_a = format!("/ip4/127.0.0.1/udp/{port_a}/quic-v1/p2p/{peer_id_a}");
    //    let multiaddr_b = format!("/ip4/127.0.0.1/udp/{port_b}/quic-v1/p2p/{peer_id_a}");
    //}

    //fn create_single_peer() -> Peer {
    //    let config = Config {
    //        listen_port: 6000,
    //        priv_key: None,
    //        known_peers: None,
    //        bootstrap: false,
    //    };

    //    let keypair = Keypair::generate_ed25519();
    //    let peer = Peer::build(&config, keypair).unwrap();

    //    peer
    //}

    //async fn create_pair_nodes() -> (
    //    (Peer, Swarm<kad::Behaviour<MemoryStore>>),
    //    (Peer, Swarm<kad::Behaviour<MemoryStore>>),
    //) {
    //    let node_a = Peer::build(&Config {
    //        listen_port: 6000,
    //        peer_node: "/ip4/127.0.0.1/tcp/6001".parse().unwrap(),
    //    })
    //    .unwrap();
    //    let node_b = Peer::build(&Config {
    //        listen_port: 6001,
    //        peer_node: "/ip4/127.0.0.1/tcp/6000".parse().unwrap(),
    //    })
    //    .unwrap();

    //    (node_a, node_b)
    //}

    //fn adding_peer_from_identify() {
    //    let peer = create_single_peer();
    //
    //    let new_peer_keypair = Keypair::generate_ed25519();
    //    let new_peer_id = PeerId::from_public_key(&new_peer_keypair.public());

    //}
}
