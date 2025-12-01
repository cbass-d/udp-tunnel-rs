use rand_core::RngCore;
use std::{ffi::OsString, fs};

use anyhow::Result;
use clap::Parser;
use libp2p::Multiaddr;
use libp2p_identity::Keypair;
use log::{LevelFilter, debug, info};
use rand_core::OsRng;
use tokio::{signal::ctrl_c, task::JoinSet};
use tunnel::{
    WgMeshError,
    config::{CliArgs, Config},
    peer::Peer,
};

const KEY_LEN: usize = 68;

pub fn init_log() {
    env_logger::builder()
        .filter_module("tunnel::node", LevelFilter::max())
        .filter_module("tunnel::peer", LevelFilter::max())
        .filter_module("tunnel", LevelFilter::max())
        .init();
}

// Read in keyfile (ed25519 previously encoded by Keypair::protobuf_encoding)
fn read_key_flie(file: &OsString) -> Result<Keypair, WgMeshError> {
    debug!("reading key file from: {:?}", file);
    let key_bytes = fs::read(file).map_err(WgMeshError::Io)?;
    let key_bytes = key_bytes.trim_ascii();

    let len = key_bytes.len();
    match len {
        KEY_LEN => {
            let keypair = Keypair::from_protobuf_encoding(&key_bytes)
                .map_err(|e| WgMeshError::InvalidKeyFile(e.to_string()))?;

            debug!("successully read ed25519 key file");

            Ok(keypair)
        }
        _ => Err(WgMeshError::InvalidKeyFile(format!(
            "invalid key len: {len}, expected {KEY_LEN}"
        ))),
    }
}

//fn read_peer_list(file: &OsString) -> Vec<Multiaddr> {
//    let peers: KnownPeers = confy::load_path(file).unwrap();
//
//    peers.peers
//}

#[tokio::main]
pub async fn main() -> Result<(), WgMeshError> {
    init_log();

    let cli_args = CliArgs::parse();

    let mut config: Config = if let Some(conf_file) = &cli_args.conf_file {
        confy::load_path(conf_file).map_err(|e| WgMeshError::FailedToLoadConf(e.to_string()))?
    } else {
        confy::load("wg-mesh", Some("wg-mesh-conf"))
            .map_err(|e| WgMeshError::FailedToLoadConf(e.to_string()))?
    };

    println!("{:?}", config);

    let cancel_token = tokio_util::sync::CancellationToken::new();

    // We either read in the private ed25519 from the given file
    // or we generate a new one and write it to a file
    let keypair = if let Some(key_file) = config.priv_key.clone() {
        debug!("using key file from CLI");
        read_key_flie(&key_file.into())?
    } else {
        debug!("generating random ed25519 key to use");
        let keypair = Keypair::generate_ed25519();
        let keyfile = format!("peer_{}.key", OsRng.next_u32());
        fs::write(
            keyfile.clone(),
            &keypair
                .to_protobuf_encoding()
                .map_err(|e| WgMeshError::DecodeError(e.to_string()))?,
        )
        .map_err(WgMeshError::Io)?;

        info!("generated ed25519 key written to \"{}\"", keyfile);

        config.priv_key = Some(keyfile);

        keypair
    };

    // Store the updated conf file
    if let Some(conf_file) = &cli_args.conf_file {
        confy::store_path(conf_file, &config)
            .map_err(|e| WgMeshError::FailedToStoreConf(e.to_string()))?;
    } else {
        confy::store("wg-mesh", "wg-mesh-conf", &config)
            .map_err(|e| WgMeshError::FailedToStoreConf(e.to_string()))?;
    }

    let mut tasks = JoinSet::new();

    let mut peer = Peer::build(&config, keypair)?;

    if !config.is_bootstrap && config.known_peers.is_empty() {
        return Err(WgMeshError::NoPeerNodes);
    }

    // Read list of alredy known peers, if any
    // Passed as a file through the CLI
    let known_peers = config.known_peers.clone();

    {
        let token = cancel_token.clone();
        tasks.spawn(async move { peer.run(&config, known_peers, token).await });
    }

    // When ctrl + c is hit, signal to stop all tasks
    // is sent
    let _ = ctrl_c().await;
    cancel_token.cancel();

    // We wait for all tasks to finish
    tasks.join_all().await;
    Ok(())
}
