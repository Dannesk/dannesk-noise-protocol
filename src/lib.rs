//! The encrypted socket between a Dannesk app and the proxy.


pub mod handshake;
#[cfg(feature = "tokio")]
pub mod stream;

pub use handshake::{
    Error, Initiator, InitiatorSent, Receiver, Responder, ResponderReplying, Sender, Session,
    StaticKey,
};
