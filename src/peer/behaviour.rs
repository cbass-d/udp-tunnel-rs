use libp2p::{
    gossipsub::{self, Behaviour as Gossipsub},
    identify::{self, Behaviour as Identify},
    kad::{self, Behaviour as Kademlia, store::MemoryStore},
    swarm::NetworkBehaviour,
};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "WgMeshEvent")]
pub struct WgMeshBehaviour {
    pub identify: Identify,
    pub kademlia: Kademlia<MemoryStore>,
    pub gossipsub: Gossipsub,
}

#[derive(Debug)]
pub enum WgMeshEvent {
    Identify(identify::Event),
    Kademlia(kad::Event),
    Gossipsub(gossipsub::Event),
}

impl From<identify::Event> for WgMeshEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<kad::Event> for WgMeshEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kademlia(event)
    }
}
impl From<gossipsub::Event> for WgMeshEvent {
    fn from(event: gossipsub::Event) -> Self {
        Self::Gossipsub(event)
    }
}
