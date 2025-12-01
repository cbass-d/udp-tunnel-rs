use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use std;
use std::ffi::OsString;

use clap::Parser;

#[derive(Parser, Debug)]
pub struct CliArgs {
    #[arg(short, long)]
    pub conf_file: Option<OsString>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Config {
    pub listen_port: u16,
    pub is_bootstrap: bool,
    pub known_peers: Vec<Multiaddr>,
    pub priv_key: Option<String>,
}
