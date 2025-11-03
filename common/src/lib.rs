pub mod errors;

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Serialize, Deserialize, Debug)]
pub struct ClientHelloMessage {}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerHelloMessage {
    pub assigned_ip: Ipv4Addr,
}
