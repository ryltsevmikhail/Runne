//! Bootstrap handshake message types (Schema v1).
//!
//! Five message types exchanged during the protocol negotiation phase:
//! HostHello → PluginHello → (NegotiationRejected | ProfileSelected) → SelectionAcknowledged.

include!("bootstrap/types.rs");
include!("bootstrap/codec.rs");
include!("bootstrap/decode_helpers.rs");
include!("bootstrap/encode_helpers.rs");
