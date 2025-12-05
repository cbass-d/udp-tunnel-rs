use std::{collections::HashMap, time::Duration};

use libp2p::{
    Multiaddr, PeerId, SwarmBuilder,
    gossipsub::{
        Behaviour as Gossipsub, ConfigBuilder as GossipConfigBuilder, MessageAuthenticity,
    },
    identify::{Behaviour as Identify, Config as IdentifyConfig},
    identity::Keypair,
    kad::{Behaviour as Kademlia, Config as KadConfig, store::MemoryStore},
};
use libp2p_identity::ed25519::{self, SecretKey};

use crate::{
    WgMeshError,
    peer::{
        IPFS_KAD_PROTO_NAME, IPFS_PROTO_NAME, Peer, WG_MESH_AGENT, behaviour::WgMeshBehaviour,
        kad_handler::KadQueries,
    },
};

pub struct PeerBuilder {
    keypair: Option<Keypair>,
    is_exit: bool,
    is_bootstrap: bool,
    known_peers: Vec<Multiaddr>,
}

impl PeerBuilder {
    pub fn new() -> Self {
        Self {
            keypair: None,
            is_exit: false,
            is_bootstrap: false,
            known_peers: vec![],
        }
    }

    pub fn set_priv_key(&mut self, priv_key: SecretKey) {
        let keypair = ed25519::Keypair::from(priv_key.clone());

        // Convert from ed25519::Keypair to libp2p_identity::Keypair
        let keypair = Keypair::from(keypair);

        self.keypair = Some(keypair);
    }

    pub fn exit(&mut self, is_exit: bool) {
        self.is_exit = is_exit;
    }

    pub fn bootstrap(&mut self, is_bootstrap: bool) {
        self.is_bootstrap = is_bootstrap;
    }

    pub fn known_peers(&mut self, known_peers: Vec<Multiaddr>) {
        self.known_peers = known_peers;
    }

    pub fn build(&mut self) -> Result<Peer, WgMeshError> {
        let keypair = if let Some(keypair) = self.keypair.take() {
            keypair
        } else {
            return Err(WgMeshError::NoPrivateKey);
        };

        let peer_id = PeerId::from_public_key(&keypair.public());

        let swarm = {
            // Identify is used to distribute info such as public keys, listen addresses, etc.
            // among peers
            let identify = {
                let cfg = IdentifyConfig::new(IPFS_PROTO_NAME.to_string(), keypair.public())
                    .with_agent_version(WG_MESH_AGENT.to_string());

                Identify::new(cfg)
            };

            // KAD is used for peer routing and discovery in the mesh network
            let kademlia: Kademlia<MemoryStore> = {
                let mut cfg = KadConfig::new(IPFS_KAD_PROTO_NAME);
                cfg.set_query_timeout(Duration::from_secs(60));
                cfg.set_periodic_bootstrap_interval(Some(Duration::from_secs(200)));

                let store = MemoryStore::new(peer_id);
                Kademlia::with_config(peer_id, store, cfg)
            };

            // Gossipsub is used for sending messages between peers using
            // topics. Peers subscribe to these topics to recieve messages
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

            let behaviour = WgMeshBehaviour {
                identify,
                //request_response,
                gossipsub,
                kademlia,
            };

            // Swarm uses quic for the transport layer for fast handshakes and connection
            // establishment
            let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
                .with_tokio()
                .with_quic()
                .with_behaviour(|_key| behaviour)
                .map_err(|e| WgMeshError::SwarmBuild(e.to_string()))?
                .build();

            swarm
        };

        Ok(Peer {
            id: peer_id,
            peers: HashMap::new(),
            swarm,
            keypair,
            subscribed: false,
            init_sent: false,
            is_bootstrap: self.is_bootstrap,
            is_exit: self.is_exit,
            known_peers: self.known_peers.clone(),
            bootstrapped: false,
            kad_queries: KadQueries::default(),
        })
    }
}
