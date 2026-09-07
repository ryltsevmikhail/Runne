//! runne-inference-protocol: private authenticated host protocol V1
//! (PROTOCOL.md). Deterministic CBOR framing, HMAC handshake, strict
//! per-direction sequence checking.

pub mod auth;
pub mod backend;
pub mod backend_codec;
mod backend_decode;
pub mod cbor;
pub mod codec;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod message;
mod protocol_body;
pub mod request;
pub mod stream;
pub mod worker_wire;

pub use auth::{
    ContextMaterial, Direction, LaunchSecret, SESSION_PURPOSE, SessionKeys, WORKER_PURPOSE, hmac,
    ikm_from_label,
};
pub use backend::{
    WORKER_ITEM_KINDS, WORKER_TERMINAL_REASONS, WorkerBackendConfig, WorkerErrorCode,
    WorkerFrameV1, WorkerLoad,
};
pub use cbor::Cbor;
pub use error::ProtocolError;
pub use frame::{
    Frame, MAX_CONTROL_FRAME, MAX_REQUEST_FRAME, MAX_STREAM_ITEM_FRAME, WIRE_VERSION, decode_frame,
    encode_frame,
};
pub use message::MessageV1;
pub use protocol_body::{ProtocolBody, decode_body, encode_body};
pub use stream::Session;
pub use worker_wire::{UnixWorkerWire, WorkerWire};
