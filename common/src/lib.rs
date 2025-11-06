pub mod errors;
pub mod messages;

pub enum ClientState {
    Handshaking,
    Connected,
    Closed,
}
