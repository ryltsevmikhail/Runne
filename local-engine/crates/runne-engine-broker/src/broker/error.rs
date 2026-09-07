//! Broker errors (security crate). Debug names are contract surface.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrokerError {
    BadDigestFormat,
    OpenFailed(String),
    NotRegularFile,
    LengthMismatch,
    IdentityUnstable,
    SymlinkRejected,
    GrantMissing,
    GrantExpired,
    AlreadyConsumed,
    AlreadyRevoked,
    WrongRole,
    WrongGeneration,
    WrongLoadId,
    WrongSession,
    EvidenceInsufficient,
    FdCountUnexpected,
    FdCloexecMissing,
    Transport(String),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::BadDigestFormat => "digest format invalid",
            Self::OpenFailed(m) => return write!(f, "open failed: {m}"),
            Self::NotRegularFile => "artifact is not a regular file",
            Self::LengthMismatch => "artifact length mismatch",
            Self::IdentityUnstable => "artifact identity changed during open",
            Self::SymlinkRejected => "symlink rejected (no-follow)",
            Self::GrantMissing => "grant id unknown",
            Self::GrantExpired => "grant expired",
            Self::AlreadyConsumed => "grant already consumed",
            Self::AlreadyRevoked => "grant already revoked",
            Self::WrongRole => "recipient role mismatch",
            Self::WrongGeneration => "host/worker generation mismatch",
            Self::WrongLoadId => "load id mismatch",
            Self::WrongSession => "session mismatch",
            Self::EvidenceInsufficient => "close evidence insufficient for role",
            Self::FdCountUnexpected => "unexpected ancillary fd count",
            Self::FdCloexecMissing => "received fd lacks close-on-exec",
            Self::Transport(m) => return write!(f, "fd transport: {m}"),
        };
        write!(f, "{text}")
    }
}

impl std::error::Error for BrokerError {}
