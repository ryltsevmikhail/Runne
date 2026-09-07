//! Protocol errors. Debug names are stable contract surface.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    Oversize,
    TrailingBytes,
    Truncated,
    NonCanonical,
    DuplicateKey,
    Malformed,
    UnknownType,
    ProtocolMismatch,
    MacMismatch,
    SequenceGap,
    Reflection,
    AuthenticationFailed,
    IdentityMismatch,
    UnknownField,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Oversize => "frame exceeds negotiated bound",
            Self::TrailingBytes => "trailing bytes after CBOR item",
            Self::Truncated => "frame truncated",
            Self::NonCanonical => "non-canonical CBOR encoding",
            Self::DuplicateKey => "duplicate map key",
            Self::Malformed => "malformed CBOR item",
            Self::UnknownType => "unknown message type",
            Self::ProtocolMismatch => "no compatible protocol version",
            Self::MacMismatch => "MAC verification failed",
            Self::SequenceGap => "transport sequence gap or replay",
            Self::Reflection => "direction mismatch (reflection)",
            Self::AuthenticationFailed => "authentication failed",
            Self::IdentityMismatch => "session/generation identity mismatch",
            Self::UnknownField => "unknown mandatory field",
        };
        write!(f, "{text}")
    }
}

impl std::error::Error for ProtocolError {}
