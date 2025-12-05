use std::{fs, io};

use boringtun::x25519::{self, StaticSecret};
use libp2p::PeerId;
use libp2p_identity::{
    Keypair,
    ed25519::{self, SecretKey},
};
use log::{debug, info};
use rand_core::{OsRng, RngCore};

const P2P_KEY_LEN: usize = 32;
const WG_KEY_LEN: usize = 32;

use crate::WgMeshError;

// Generate the ed25519 (used for p2p) and x25519 (used for Wireguard) keys
// Both are written to a file in the current working directory for now
pub fn gen_keys() -> Result<(), WgMeshError> {
    debug!("generating random ed25519 key for p2p to use");

    let priv_key = ed25519::SecretKey::generate();
    let keyfile = format!("peer_{}.key", OsRng.next_u32());

    write_key_to_file(priv_key.as_ref(), &keyfile).map_err(WgMeshError::Io)?;

    info!("generated ed25519 key written to \"{}\"", keyfile);

    let keypair: Keypair = ed25519::Keypair::from(priv_key).into();
    let peer_id = PeerId::from_public_key(&keypair.public());

    info!("peer id: {}", peer_id);

    debug!("generating random x25519 secret key for Wireguard to use");

    let secret_key = x25519::StaticSecret::random_from_rng(OsRng);
    let keyfile = format!("wg_{}.key", OsRng.next_u32());

    write_key_to_file(secret_key.as_ref(), &keyfile).map_err(WgMeshError::Io)?;

    info!("generated x25519 secret key written to \"{}\"", keyfile);

    Ok(())
}

// Takes in key bytes as &[u8] and writes them to the provided file_path
pub fn write_key_to_file(key_bytes: &[u8], file_path: &str) -> Result<(), io::Error> {
    fs::write(&file_path, key_bytes)?;

    debug!("key bytes written to {:?}", file_path);

    Ok(())
}

// Takes in file path and reads the key bytes into a BytesMut
pub fn read_key_from_file(file_path: &str) -> Result<Vec<u8>, io::Error> {
    debug!("reading key file from: {:?}", file_path);

    let key_bytes = fs::read(file_path)?;

    Ok(key_bytes)
}

// We either load or generate the ed25519 key
// if we generate it we write it to a file in the current working directory
pub fn load_or_generate_ed25519(
    path: Option<&String>,
) -> Result<(ed25519::SecretKey, String), WgMeshError> {
    if let Some(path) = path {
        debug!("reading ed25519 key from file {:?}", path);

        let mut key_bytes = read_key_from_file(path).map_err(WgMeshError::Io)?;

        let len = key_bytes.len();
        if len != P2P_KEY_LEN {
            return Err(WgMeshError::InvalidKeyFile(format!(
                "invalid key len: {}, expected {P2P_KEY_LEN}",
                len
            )));
        }

        let secret_key = SecretKey::try_from_bytes(&mut key_bytes[..])
            .map_err(|e| WgMeshError::DecodeError(e.to_string()))?;

        return Ok((secret_key, path.to_string()));
    }

    debug!("generating random ed25519 key to use");

    let secret_key = SecretKey::generate();
    let keyfile = format!("peer_{}.key", OsRng.next_u32());
    write_key_to_file(secret_key.as_ref(), &keyfile).map_err(WgMeshError::Io)?;

    Ok((secret_key, keyfile))
}

// We either load or generate the x25519 static secret
// if we generate it we write it to a file in the current working directory
pub fn load_or_generate_x25519(
    path: Option<&String>,
) -> Result<(x25519::StaticSecret, String), WgMeshError> {
    if let Some(path) = path {
        debug!("reading x25519 key from file {:?}", path);

        let key_bytes = read_key_from_file(path).map_err(WgMeshError::Io)?;

        let len = key_bytes.len();
        if len != WG_KEY_LEN {
            return Err(WgMeshError::InvalidKeyFile(format!(
                "invalid key len: {}, expected {WG_KEY_LEN}",
                len
            )));
        }

        let key_bytes: [u8; 32] = match key_bytes.try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(WgMeshError::DecodeError(
                    "failed to convert key bytes to [u8; 32]".to_string(),
                ));
            }
        };

        let static_secret = StaticSecret::from(key_bytes);

        return Ok((static_secret, path.to_string()));
    }

    debug!("generating random x25519 static secret to use");

    let static_secret = StaticSecret::random_from_rng(OsRng);
    let keyfile = format!("wg_{}.key", OsRng.next_u32());
    write_key_to_file(static_secret.as_ref(), &keyfile).map_err(WgMeshError::Io)?;

    Ok((static_secret, keyfile))
}
