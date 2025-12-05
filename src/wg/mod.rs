use boringtun::x25519;

pub struct WireguardInterface {
    pub static_secret: x25519::StaticSecret,
    pub static_pub: x25519::PublicKey,
}

impl WireguardInterface {}
