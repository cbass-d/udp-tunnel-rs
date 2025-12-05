use libp2p::identify::{self, Event};
use log::{debug, info, warn};

use crate::{
    WgMeshError,
    peer::{Peer, WG_MESH_AGENT},
    util::is_private_ip,
};

pub fn handle_event(peer: &mut Peer, event: identify::Event) -> Result<(), WgMeshError> {
    match event {
        Event::Received { peer_id, info, .. } => {
            info!("identify recv event {:?}", info);

            if info.agent_version == WG_MESH_AGENT && !peer.peers.contains_key(&peer_id) {
                let mut good_addrs = vec![];
                for addr in info.listen_addrs.into_iter() {
                    if !is_private_ip(&addr) {
                        if peer.swarm.dial(addr.clone()).is_ok() {
                            info!("dialed peer {addr} from identify recv");
                            good_addrs.push(addr);
                        } else {
                            warn!("failed to dial peer {addr} from identify recv");
                        }
                    }
                }

                if !good_addrs.is_empty() {
                    // Add wg mesh peer
                    peer.add_peer(peer_id, good_addrs, info.public_key);
                }
            }
        }

        Event::Sent { peer_id, .. } => {
            info!("identify sent event to {peer_id}");
        }
        Event::Pushed { peer_id, info, .. } => {
            info!("identify pushed event to {peer_id} {:?}", info);
        }
        Event::Error { peer_id, error, .. } => match error {
            libp2p::swarm::StreamUpgradeError::Timeout => {
                peer.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
            }
            _ => {
                debug!("identify error: {error}");
            }
        },
    }

    Ok(())
}
