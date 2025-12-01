use anyhow::anyhow;
use libp2p::{PeerId, gossipsub::Event};
use serde::{Deserialize, Serialize};

const GOSSIPSUB_WG_MESH_CHANNEL: &str = "wg-mesh-channel";

#[derive(Debug, Clone)]
pub enum WgMeshMessage {
    Intro {
        propagation_source: PeerId,
        from: Option<PeerId>,
        info: Info,
        seq_no: Option<u64>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Info {
    pub is_bootstrap: Option<bool>,
}

impl TryFrom<Event> for WgMeshMessage {
    type Error = anyhow::Error;

    fn try_from(event: Event) -> anyhow::Result<Self, Self::Error> {
        if let Event::Message {
            propagation_source,
            message,
            ..
        } = event
        {
            let from = message.source;
            let data = message.data;
            let seq_no = message.sequence_number;
            let topic = message.topic;

            let info = match serde_json::from_slice::<Info>(&data) {
                Ok(info) => info,
                Err(e) => {
                    return Err(anyhow!("Invalid message data: {e}"));
                }
            };

            match topic.as_str() {
                GOSSIPSUB_WG_MESH_CHANNEL => Ok(Self::Intro {
                    propagation_source,
                    from,
                    info,
                    seq_no,
                }),
                _ => Err(anyhow!("Invalid gossibsub message")),
            }
        } else {
            Err(anyhow!("invalid gossibsub event"))
        }
    }
}
