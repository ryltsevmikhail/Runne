#![forbid(unsafe_code)]
//! gocode-plugin-protocol — wire primitives, deterministic CBOR,
//! bootstrap handshake, frame codec. No external dependencies.

pub mod bootstrap;
pub mod cbor;
pub mod digest;
pub mod frame;
pub mod id;
pub mod profile;
pub mod session;
