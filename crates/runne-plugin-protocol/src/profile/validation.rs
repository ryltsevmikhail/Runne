/// Session and negotiation validation errors — separate from wire-level DecodeError.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolValidationError {
    /// Profile was not in the supported set.
    ProfileNotSupported,
    /// Protocol versions are incompatible.
    ProtocolVersionMismatch {
        expected: ProtocolVersion,
        actual: ProtocolVersion,
    },
    /// Sequence number gap detected.
    SequenceGap { expected: u64, actual: u64 },
    /// Session ID mismatch.
    SessionMismatch,
    /// Profile ID or digest mismatch.
    ProfileMismatch,
    /// Payload digest does not match actual payload.
    PayloadDigestMismatch,
    /// Message digest does not match.
    MessageDigestMismatch,
    /// Correlation ID mismatch.
    CorrelationMismatch,
    /// Host or plugin identity mismatch.
    IdentityMismatch,
    /// Deadline is in the past or otherwise invalid.
    DeadlineInvalid,
}

impl std::fmt::Display for ProtocolValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProfileNotSupported => write!(f, "profile not supported"),
            Self::ProtocolVersionMismatch { expected, actual } => {
                write!(
                    f,
                    "protocol version mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Self::SequenceGap { expected, actual } => {
                write!(f, "sequence gap: expected {}, got {}", expected, actual)
            }
            Self::SessionMismatch => write!(f, "session ID mismatch"),
            Self::ProfileMismatch => write!(f, "profile mismatch"),
            Self::PayloadDigestMismatch => write!(f, "payload digest mismatch"),
            Self::MessageDigestMismatch => write!(f, "message digest mismatch"),
            Self::CorrelationMismatch => write!(f, "correlation mismatch"),
            Self::IdentityMismatch => write!(f, "identity mismatch"),
            Self::DeadlineInvalid => write!(f, "deadline is invalid"),
        }
    }
}

impl std::error::Error for ProtocolValidationError {}
