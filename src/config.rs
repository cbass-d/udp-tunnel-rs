use libp2p::Multiaddr;
use log::debug;
use serde::{Deserialize, Serialize};

use clap::Parser;

use crate::WgMeshError;

#[derive(Parser, Debug)]
pub struct CliArgs {
    #[arg(short, long)]
    pub gen_key: Option<bool>,
    #[arg(short, long)]
    pub conf_file: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub listen_port: u16,
    pub is_bootstrap: bool,
    pub is_exit: bool,
    pub known_peers: Vec<Multiaddr>,
    pub p2p_priv_key: Option<String>,
    pub wg_priv_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_port: 0,
            is_bootstrap: true,
            is_exit: true,
            known_peers: vec![],
            p2p_priv_key: None,
            wg_priv_key: None,
        }
    }
}

impl Config {
    pub fn update_keys(&mut self, p2p_key_file: Option<String>, wg_key_file: Option<String>) {
        if p2p_key_file.is_some() {
            self.p2p_priv_key = p2p_key_file;
        }

        if wg_key_file.is_some() {
            self.wg_priv_key = wg_key_file;
        }
    }
}

// Load config from conf_file if provided. If not provided, it is read from
// $XDG_CONFIG_HOME/wg-mesh/wg-mesh-conf.toml
pub fn load_config(conf_file: Option<&String>) -> Result<Config, WgMeshError> {
    let config = if let Some(conf_file) = conf_file {
        confy::load_path(&conf_file).map_err(|e| WgMeshError::FailedToLoadConf(e.to_string()))?
    } else {
        confy::load("wg-mesh", Some("wg-mesh-conf"))
            .map_err(|e| WgMeshError::FailedToLoadConf(e.to_string()))?
    };

    debug!("loaded the config: {:?}", config);

    Ok(config)
}

// Store the config to path conf_file if provided. If not provided, it is writen to
// $XDG_CONFIG_HOME/wg-mesh/wg-mesh-conf.toml
pub fn store_config(config: &Config, conf_file: Option<&String>) -> Result<(), WgMeshError> {
    if let Some(conf_file) = conf_file {
        confy::store_path(&conf_file, config)
            .map_err(|e| WgMeshError::FailedToStoreConf(e.to_string()))?
    } else {
        confy::store("wg-mesh", "wg-mesh-conf", config)
            .map_err(|e| WgMeshError::FailedToStoreConf(e.to_string()))?
    };

    debug!("stored the config: {:?}", config);

    Ok(())
}
