use libp2p::{
    gossipsub::Behaviour as Gossipsub,
    identify::Behaviour as Identify,
    kad::{Behaviour as Kademlia, store::MemoryStore},
    request_response::{self, Behaviour as RequestResponse},
    swarm::NetworkBehaviour,
};

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub identify: Identify,
    pub kademlia: Kademlia<MemoryStore>,
    pub gossipsub: Gossipsub,
    //pub request_response: request_response::json::Behaviour<, GreetResponse>,
}
