use libp2p::{
    PeerId,
    kad::{self, GetRecordOk, InboundRequest, ProgressStep, QueryId, QueryResult, RecordKey},
};
use log::{debug, error, info, warn};

use crate::{
    WgMeshError,
    peer::{Peer, WG_MESH_AGENT},
};

pub fn handle_event(peer: &mut Peer, event: kad::Event) -> Result<(), WgMeshError> {
    match event {
        kad::Event::InboundRequest { request } => {
            on_inbound_req(peer, request);
        }
        kad::Event::OutboundQueryProgressed {
            result, id, step, ..
        } => {
            on_query_result(peer, result, id, step);
        }
        kad::Event::RoutingUpdated {
            peer, addresses, ..
        } => {
            info!("route updated for {peer}: {:?}", addresses);
        }
        kad::Event::RoutablePeer { peer, address, .. } => {
            info!("peer {peer} {:?} routable", address);
        }
        kad::Event::PendingRoutablePeer { peer, address, .. } => {
            info!("peer {peer} {:?} pending routable", address);
        }
        kad::Event::ModeChanged { new_mode } => {
            info!("node mode changed to {new_mode}");
        }
        other => {
            debug!("some other kad event: {:?}", other);
        }
    }
    Ok(())
}

fn on_inbound_req(peer: &mut Peer, request: InboundRequest) {
    match request {
        InboundRequest::FindNode { num_closer_peers } => {}
        InboundRequest::GetProvider {
            num_closer_peers,
            num_provider_peers,
        } => {}
        InboundRequest::GetRecord {
            num_closer_peers,
            present_locally,
        } => {}
        InboundRequest::AddProvider { record } => {}
        InboundRequest::PutRecord {
            source,
            connection,
            record,
        } => {}
    }
}

fn on_query_result(peer: &mut Peer, result: QueryResult, id: QueryId, step: ProgressStep) {
    match result {
        QueryResult::Bootstrap(Ok(res)) => {
            if let Some(qid) = peer.kad_queries.bootsrap_id {
                if id == qid {
                    if step.last {
                        peer.kad_queries.bootsrap_id = None;
                        peer.bootstrapped = true;

                        info!("kademlia bootstrapped");

                        // Once the bootstrap nodes are connected to other
                        // bootstrap nodes we can set them to server mode
                        //if peer.is_bootstrap {
                        //    peer.swarm
                        //        .behaviour_mut()
                        //        .kademlia
                        //        .set_mode(Some(Mode::Server));
                        //}

                        // Get other providers of the agent string to
                        // get info about mesh

                        let key = RecordKey::new(&WG_MESH_AGENT);
                        let qid = peer.swarm.behaviour_mut().kademlia.get_providers(key);

                        peer.kad_queries.get_providers_id = Some(qid);
                    } else {
                        debug!(
                            "kademlia bootstrapping peer {}, remaining {}",
                            res.peer, res.num_remaining
                        )
                    }
                }
            }
        }
        QueryResult::Bootstrap(Err(e)) => {
            warn!("failed to bootstrap error: {e}");
            peer.kad_queries.bootsrap_id = None;
        }
        QueryResult::GetClosestPeers(Ok(closest_res)) => {
            let key = PeerId::from_bytes(&closest_res.key);
            let peers = closest_res.peers;

            info!("closest peers for key {:?}: {:?}", key, peers);
            //peer.build_mesh(peers.peers);
        }
        QueryResult::GetClosestPeers(Err(e)) => {
            warn!("get closest peers error: {e}");
        }
        QueryResult::GetProviders(Ok(providers)) => {
            if let Some(qid) = peer.kad_queries.get_providers_id {
                if id == qid {
                    match providers {
                        kad::GetProvidersOk::FoundProviders { key, providers } => {
                            let key = String::from_utf8(key.to_vec());
                            info!("found providers for {:?}:", key);
                            for provider in &providers {
                                info!("- {provider}");

                                // Get other possible/peers providers
                                peer.swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .get_closest_peers(*provider);
                            }
                            peer.kad_queries.get_providers_id = None;
                        }
                        kad::GetProvidersOk::FinishedWithNoAdditionalRecord { closest_peers } => {
                            info!("get proivders closest_peers: {:?}", closest_peers);
                            for new_peer in &closest_peers {
                                info!("- {new_peer}");

                                // Get other possible/peers providers
                                peer.swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .get_closest_peers(*new_peer);
                            }
                        }
                    }
                }
            }
        }
        QueryResult::GetProviders(Err(e)) => {
            if let Some(qid) = peer.kad_queries.get_providers_id {
                if id == qid {
                    peer.kad_queries.get_providers_id = None;
                    error!("falied to get providers for wg mesh agent string: {e}");
                }
            }
        }
        QueryResult::StartProviding(Ok(_)) => {
            if let Some(qid) = peer.kad_queries.providing_agent_id {
                if id == qid && step.last {
                    peer.kad_queries.providing_agent_id = None;
                    debug!("node providing wg mesh agent string");
                }
            }
        }
        QueryResult::StartProviding(Err(e)) => {
            warn!("start providing error: {e}");

            if let Some(qid) = peer.kad_queries.providing_agent_id {
                if id == qid {
                    error!("failed to provide wg agent string");
                    peer.kad_queries.providing_agent_id = None;
                }
            }
        }
        QueryResult::RepublishRecord(_) => {
            debug!("handling republish record result");
        }
        QueryResult::GetRecord(Ok(record_res)) => {
            match record_res {
                GetRecordOk::FoundRecord(record) => {
                    info!("found record {:?} at {:?}", record.record, record.peer);
                }
                _ => {
                    debug!("get record finished with no additional records");
                }
            }
            debug!("get record result");
        }
        QueryResult::GetRecord(Err(e)) => {
            warn!("get record error: {e}");
        }
        QueryResult::PutRecord(Ok(res)) => {
            let key = String::from_utf8(res.key.to_vec());
            debug!("put record result: {:?}", key);
        }
        QueryResult::PutRecord(Err(e)) => {
            debug!("put record error: {e}");
        }
        QueryResult::RepublishProvider(_) => {
            debug!("handling republish provider result");
        }
        other => {
            debug!("some other query result: {:?}", other);
        }
    }
}

// Id's of important kad queries
#[derive(Default, Debug)]
pub struct KadQueries {
    pub bootsrap_id: Option<QueryId>,
    pub providing_agent_id: Option<QueryId>,
    pub get_providers_id: Option<QueryId>,
}
