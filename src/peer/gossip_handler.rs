use libp2p::gossipsub::Event;
use log::{debug, info};

use crate::{WgMeshError, message::WgMeshMessage, peer::Peer};

pub fn handle_event(peer: &mut Peer, event: Event) -> Result<(), WgMeshError> {
    match event {
        Event::Message { .. } => {
            if let Ok(wg_mesh_message) = WgMeshMessage::try_from(event) {
                info!("message recieved: {:?}", wg_mesh_message);
            }
        }
        Event::Subscribed { peer_id, topic } => {
            if peer_id == peer.id {
                info!("Successfully subscribed to {topic}");
            }
        }
        other => {
            debug!("gossipsub event: {:?}", other);
        }
    }

    Ok(())
}
