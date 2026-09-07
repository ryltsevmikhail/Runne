//! Closed message-catalog abstraction shared by protocol sessions.

use crate::cbor::Cbor;
use crate::codec::{decode_message_body, encode_message_body};
use crate::error::ProtocolError;
use crate::message::MessageV1;

/// A closed message catalog transportable by `Session`.
pub trait ProtocolBody: Sized {
    fn type_name(&self) -> &'static str;
    fn encode_body(&self) -> Cbor;
    fn decode_body(type_name: &str, body: &Cbor) -> Result<Self, ProtocolError>;
}

impl ProtocolBody for MessageV1 {
    fn type_name(&self) -> &'static str {
        crate::message::type_name(self)
    }

    fn encode_body(&self) -> Cbor {
        encode_message_body(self)
    }

    fn decode_body(type_name: &str, body: &Cbor) -> Result<Self, ProtocolError> {
        decode_message_body(type_name, body)
    }
}

/// Free-function form kept for direct callers (handshake transcript).
pub fn encode_body(message: &MessageV1) -> Cbor {
    encode_message_body(message)
}

pub fn decode_body(type_name: &str, body: &Cbor) -> Result<MessageV1, ProtocolError> {
    decode_message_body(type_name, body)
}
