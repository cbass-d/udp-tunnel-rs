use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};

pub fn split_peer_id(addr: Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut base_addr = Multiaddr::empty();
    let mut peer_id = None;

    for component in addr.into_iter() {
        if let Protocol::P2p(id) = component {
            peer_id = Some(id);
            break;
        } else {
            base_addr.push(component);
        }
    }

    peer_id.map(|id| (id, base_addr))
}
