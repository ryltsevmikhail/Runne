// The decoder is intentionally crate-private until a provider-owned ingress consumes it.
#[allow(dead_code)]
mod codec;
mod command;
mod command_codec;
#[cfg(test)]
#[path = "protocol/command_tests.rs"]
mod command_tests;

#[cfg(test)]
mod tests;

pub use codec::CredentialBrokerFrameCodec;
pub use command::{CredentialBrokerCommand, CredentialBrokerTarget};
pub use command_codec::CredentialBrokerCommandCodec;

use super::{
    CredentialBindingDigest, CredentialDisposition, CredentialOperationId, CredentialTicketAttempt,
    RawCredentialTicket,
};

/// Closed broker-control frames; native claims and credential bytes are absent.
pub enum CredentialBrokerFrame {
    /// Daemon sends a one-shot raw ticket over the inherited channel.
    IssueTicket {
        /// Durable operation identity.
        operation_id: CredentialOperationId,
        /// One-shot ticket attempt.
        attempt: CredentialTicketAttempt,
        /// Opaque raw ticket.
        ticket: RawCredentialTicket,
    },
    /// Writer returns the raw ticket and immutable claim-binding digest.
    Claim {
        /// Durable operation identity.
        operation_id: CredentialOperationId,
        /// One-shot ticket attempt.
        attempt: CredentialTicketAttempt,
        /// Opaque raw ticket.
        ticket: RawCredentialTicket,
        /// Immutable claim-binding digest.
        binding: CredentialBindingDigest,
    },
    /// Daemon accepted the claimed ticket attempt.
    ClaimAccepted {
        /// Durable operation identity.
        operation_id: CredentialOperationId,
        /// Accepted ticket attempt.
        attempt: CredentialTicketAttempt,
    },
    /// Daemon denied the claimed ticket attempt without secret disclosure.
    ClaimDenied {
        /// Durable operation identity.
        operation_id: CredentialOperationId,
        /// Denied ticket attempt.
        attempt: CredentialTicketAttempt,
        /// Safe denial category.
        disposition: CredentialDisposition,
    },
    /// Writer reports only a possible native effect with its bound transcript.
    NativeEffectObserved {
        /// Durable operation identity.
        operation_id: CredentialOperationId,
        /// Bound native-effect transcript digest.
        binding: CredentialBindingDigest,
    },
}
