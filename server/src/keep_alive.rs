use crate::{
    KeepAliveMessage, KeepAliveType, UnexpectedMessage, UnexpectedSource, manager::ManagerMessages,
};
use anyhow::Result;
use std::{net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::timeout};

pub async fn run(socket: &UdpSocket, peer: &SocketAddr) -> Result<()> {
    let keep_alive = {
        let msg = KeepAliveMessage {
            msg_type: KeepAliveType::Request,
        };
        serde_json::to_vec(&msg).unwrap()
    };

    match socket.send_to(&keep_alive[..], peer).await {
        Ok(_) => {
            let mut buf = [0; 1024];
            if let Ok((len, reply_peer)) =
                timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await?
            {
                if *peer != reply_peer {
                    return Err(UnexpectedSource.into());
                }

                let msg = serde_json::from_slice::<KeepAliveMessage>(&buf[..len])?;

                if msg.msg_type != KeepAliveType::Reply {
                    return Err(UnexpectedMessage.into());
                }
            }
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
