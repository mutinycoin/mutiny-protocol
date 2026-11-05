//! Pre-Genesis transport qualification. Never wallet or consensus authority.
mod frame;
mod handshake;
pub mod handshake_frames;
pub mod ingress;
pub mod objects;
pub mod object_link;
pub mod tcp;
mod primitives;
pub mod worker_context_v2;
pub mod worker_handshake_v2;
pub use frame::{MAX_PAYLOAD, Metadata, Session};
pub use handshake::{Context, Endpoint, InitiatorConfirm, InitiatorPending, ResponderPending};
pub const PRODUCTION_QUALIFIED: bool = false;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Context,
    Crypto,
    Expired,
    Replay,
    Limit,
    Storage,
}
