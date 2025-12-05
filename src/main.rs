use anyhow::Result;
use clap::{Arg, ArgAction, command};
use log::{LevelFilter, debug, info};
use tokio::{signal::ctrl_c, task::JoinSet};
use tunnel::{
    WgMeshError, config, key,
    peer::{Peer, builder::PeerBuilder},
    wg::WireguardInterface,
};

enum KeyType {
    P2P,
    WG,
}

pub fn init_log() {
    env_logger::builder()
        .filter_module("tunnel::node", LevelFilter::max())
        .filter_module("tunnel::peer", LevelFilter::max())
        .filter_module("tunnel", LevelFilter::max())
        .init();
}

#[tokio::main]
pub async fn main() -> Result<(), WgMeshError> {
    init_log();

    // Declare the CLI arguments to be read in, if any
    let matches = command!()
        .arg(
            Arg::new("gen-keys")
                .short('g')
                .long("gen-keys")
                .action(ArgAction::SetTrue),
        )
        .arg(Arg::new("conf-file").short('c').long("conf-file"))
        .get_matches();

    // If the 'gen-keys' flag is present we generate the keys and exit the program
    if matches.get_flag("gen-keys") {
        key::gen_keys()?;
        return Ok(());
    }

    // Load the application config to be used
    let mut config = config::load_config(matches.get_one::<String>("conf-file"))?;

    // We either read in the private ed25519 for libp2p from the given file
    // or we generate a new one and write it to a file
    let (p2p_key, p2p_key_file) = key::load_or_generate_ed25519(config.p2p_priv_key.as_ref())?;

    // Repeat the same process for Wireguard x25519 secret
    let (wg_key, wg_key_file) = key::load_or_generate_x25519(config.wg_priv_key.as_ref())?;

    // Update the file key paths to store in config
    config.update_keys(Some(p2p_key_file), Some(wg_key_file));

    // Store the updated conf file
    config::store_config(&config, matches.get_one::<String>("conf-file"))?;

    // If the peer is not a bootstrap and does not have the knowledge
    // of other peers to connect to, it cannot join the network
    if !config.is_bootstrap && config.known_peers.is_empty() {
        return Err(WgMeshError::NoPeerNodes);
    }

    let mut peer_builder = PeerBuilder::new();
    peer_builder.set_priv_key(p2p_key);
    peer_builder.bootstrap(config.is_bootstrap);
    peer_builder.exit(config.is_exit);
    peer_builder.known_peers(config.known_peers.clone());

    let mut peer = peer_builder.build()?;

    let cancel_token = tokio_util::sync::CancellationToken::new();
    let mut tasks = JoinSet::new();

    {
        let token = cancel_token.clone();
        tasks.spawn(async move { peer.run(&config, token).await });
    }

    // When ctrl + c is hit, signal to stop all tasks
    // is sent
    let _ = ctrl_c().await;
    cancel_token.cancel();

    // We wait for all tasks to finish
    tasks.join_all().await;
    Ok(())
}
