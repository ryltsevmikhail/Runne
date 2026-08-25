mod codec;

#[cfg(test)]
mod tests;

pub use codec::CredentialBrokerFrameCodec;

use super::{
    CredentialBindingDigest, CredentialDisposition, CredentialOperationId, CredentialTicketAttempt,
    RawCredentialTicket,
};

/// Closed broker-control frames; native claims and credential bytes are absent.
pub enum CredentialBrokerFrame {
    /// Daemon sends a one-shot raw ticket over the inherited channel.
    IssueTicket {
        operation_id: CredentialOperationId,
        attempt: CredentialTicketAttempt,
        ticket: RawCredentialTicket,
    },
    /// Writer returns the raw ticket and immutable claim-binding digest.
    Claim {
        operation_id: CredentialOperationId,
        attempt: CredentialTicketAttempt,
        ticket: RawCredentialTicket,
        binding: CredentialBindingDigest,
    },
    /// Daemon accepted the claimed ticket attempt.
    ClaimAccepted {
        operation_id: CredentialOperationId,
        attempt: CredentialTicketAttempt,
    },
    /// Daemon denied the claimed ticket attempt without secret disclosure.
    ClaimDenied {
        operation_id: CredentialOperationId,
        attempt: CredentialTicketAttempt,
        disposition: CredentialDisposition,
    },
    /// Writer reports only a possible native effect with its bound transcript.
    NativeEffectObserved {
        operation_id: CredentialOperationId,
        binding: CredentialBindingDigest,
    },
}
