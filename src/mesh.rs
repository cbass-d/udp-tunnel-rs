use core::fmt;

use libp2p::{Multiaddr, PeerId, kad::PeerInfo};
use libp2p_identity::PublicKey;

#[derive(Debug)]
pub struct MeshPeer {
    pub id: PeerId,
    pub listen_addrs: Vec<Multiaddr>,
    pub is_bootstrap: Option<bool>,
    pub pub_key: PublicKey,
}

impl MeshPeer {
    pub fn new(id: PeerId, listen_addrs: Vec<Multiaddr>, pub_key: PublicKey) -> Self {
        Self {
            id,
            listen_addrs,
            pub_key,
            is_bootstrap: None,
        }
    }

    pub fn update(
        &mut self,
        is_bootstrap: Option<bool>,
        listen_addrs: Option<Vec<Multiaddr>>,
        pub_key: Option<PublicKey>,
    ) {
        if let Some(is_bootstrap) = is_bootstrap {
            self.is_bootstrap = Some(is_bootstrap);
        }

        if let Some(addrs) = listen_addrs {
            self.listen_addrs = addrs;
        }

        if let Some(pub_key) = pub_key {
            self.pub_key = pub_key;
        }
    }
}

pub struct Mesh {
    pub root: PeerId,
    pub peers: Vec<PeerInfo>,
}

impl Mesh {
    pub fn new(root: PeerId, peers: Vec<PeerInfo>) -> Self {
        Self { root, peers }
    }
}

impl fmt::Display for Mesh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Mesh\n-> {}", self.root)?;

        if self.peers.is_empty() {
            writeln!(f, "Peers: (none)")?;
            return Ok(());
        }

        writeln!(f, "Peers")?;
        for p in &self.peers {
            writeln!(f, "\t - {:?}", p)?;
        }

        Ok(())
    }
}
