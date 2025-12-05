use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};

pub fn is_private_ip(addr: &Multiaddr) -> bool {
    for component in addr.iter() {
        match component {
            Protocol::Ip4(addr) => {
                return addr.is_private()
                    || addr.is_loopback()
                    || addr.is_link_local()
                    || addr.is_unspecified();
            }
            _ => {}
        }
    }

    false
}

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
