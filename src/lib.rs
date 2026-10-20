//! The encrypted socket between apps and the proxy.

pub mod handshake;
#[cfg(feature = "tokio")]
pub mod stream;

pub use handshake::{
    Error, Initiator, InitiatorSent, Receiver, Responder, ResponderReplying, Sender, Session,
    StaticKey,
};
