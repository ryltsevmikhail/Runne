// The decoder is intentionally crate-private until a provider-owned ingress consumes it.
#[allow(dead_code)]
mod codec;
mod command;
mod command_codec;
#[cfg(test)]
#[path = "protocol/command_tests.rs"]
mod command_tests;
#[allow(
    dead_code,
    reason = "sealed credential relay stays crate-private until the native Pair writer consumes it"
)]
mod secret;
mod session_attestation;

#[cfg(test)]
#[path = "protocol/codec_claim_tests.rs"]
mod codec_claim_tests;
#[cfg(test)]
#[path = "protocol/session_attestation_tests.rs"]
mod session_attestation_tests;
#[cfg(test)]
mod tests;

pub use codec::CredentialBrokerFrameCodec;
pub use command::{CredentialBrokerCommand, CredentialBrokerTarget};
pub use command_codec::CredentialBrokerCommandCodec;
pub use secret::{
    CredentialSecretClaimOffer, CredentialSecretEnvelopeCodec, CredentialSecretOfferCodec,
    CredentialSecretPublication, CredentialSecretPublicationCodec, CredentialSecretRelayFrameCodec,
    PendingCredentialSecretOpening, SealedCredentialEnvelope,
};
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use secret::{SealedPairFixture, sealed_pair_for_test};
pub use session_attestation::{
    CredentialIssueTicketBindingV1, CredentialSecretInputPresence, CredentialWriterCommandKindV1,
    CredentialWriterCommandScopeV1, CredentialWriterSessionAttestationClaimsV1,
    CredentialWriterSessionAttestationCodec, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1,
    PendingCredentialIssueTicketV1, SignedCredentialWriterSessionAttestationV1,
};

/// Deliberately narrow daemon-only publication adapter.
#[doc(hidden)]
pub mod daemon_credential_publication {
    pub use super::secret::DaemonCredentialSecretPublicationSigner as CredentialSecretPublicationSigner;
    pub use super::session_attestation::CredentialWriterSessionAttestationSigner;
}

/// Test-only verifier for asserting the sealed daemon publication boundary.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod daemon_credential_publication_test_support {
    use super::{CredentialSecretClaimOffer, CredentialSecretPublication};
    use crate::credential::enrollment::CredentialEnrollmentError;

    pub fn verify(
        daemon_public_key: [u8; 32],
        channel_binding: [u8; 32],
        offer: CredentialSecretClaimOffer,
        publication: CredentialSecretPublication,
    ) -> Result<(), CredentialEnrollmentError> {
        super::secret::verify_publication_for_test(
            daemon_public_key,
            channel_binding,
            offer,
            publication,
        )
    }
}

/// The only non-secret argv token accepted by the packaged credential writer.
///
/// Channel descriptors and every credential value remain inherited capabilities;
/// they are never represented in argv or environment variables.
pub const PROVIDER_CREDENTIAL_BROKER_MODE_V1: &str = "__provider-credential-broker-v1";

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
        /// Exact inherited control-channel binding, available only on the live channel.
        channel_binding: [u8; 32],
        /// Precomputed complete claim binding for this exact ticket attempt.
        binding: CredentialBindingDigest,
        /// Canonical non-secret native effect command for this exact attempt.
        command: CredentialBrokerCommand,
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
        /// Pair-only writer public offer; never contains credential material.
        secret_offer: Option<CredentialSecretClaimOffer>,
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
    /// Daemon releases the exact claimed attempt only after durable relay ACK.
    NativeEffectRelease {
        /// Durable operation identity.
        operation_id: CredentialOperationId,
        /// Exact claimed ticket attempt.
        attempt: CredentialTicketAttempt,
        /// Immutable claim-binding digest.
        binding: CredentialBindingDigest,
    },
    /// Writer reports only a possible native effect with its bound transcript.
    NativeEffectObserved {
        /// Durable operation identity.
        operation_id: CredentialOperationId,
        /// Bound native-effect transcript digest.
        binding: CredentialBindingDigest,
    },
}
