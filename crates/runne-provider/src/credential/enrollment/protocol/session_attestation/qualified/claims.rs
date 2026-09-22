use sha2::{Digest as _, Sha256};

use super::super::{CredentialWriterSessionAttestationClaimsV1, PendingCredentialIssueTicketV1};
use crate::credential::enrollment::CredentialBindingDigest;

/// Inert signed commitment selecting the required Writer qualification profile.
pub struct SignedCredentialWriterSessionAttestationV2 {
    pub(crate) claims: CredentialWriterSessionAttestationClaimsV1,
    pub(crate) channel: CredentialBindingDigest,
    pub(crate) publication_public_key: [u8; 32],
    pub(crate) launch_generation: u64,
    pub(crate) context_sha256: CredentialBindingDigest,
    pub(crate) ticket_sha256: CredentialBindingDigest,
    pub(crate) signature: [u8; 64],
}

impl core::fmt::Debug for SignedCredentialWriterSessionAttestationV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SignedCredentialWriterSessionAttestationV2(<inert-signed>)")
    }
}

impl SignedCredentialWriterSessionAttestationV2 {
    /// Digest of the complete canonical record, including its signature.
    #[must_use]
    pub fn full_digest(&self) -> [u8; 32] {
        Sha256::digest(super::codec::CredentialWriterSessionAttestationV2Codec::encode(self)).into()
    }

    /// Returns the committed canonical context digest.
    #[must_use]
    pub fn context_sha256(&self) -> [u8; 32] {
        self.context_sha256.as_bytes()
    }

    /// Returns the committed canonical ticket digest.
    #[must_use]
    pub fn ticket_sha256(&self) -> [u8; 32] {
        self.ticket_sha256.as_bytes()
    }

    /// Returns the authenticated Writer launch generation.
    #[must_use]
    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }

    /// Compares the signed ticket commitment to the exact prefetched ticket.
    #[must_use]
    pub fn matches_pending_issue_ticket(&self, pending: &PendingCredentialIssueTicketV1) -> bool {
        pending.matches_attested(&self.claims.ticket.issue_ticket)
    }

    /// Compares handoff facts against the independently authenticated channel.
    #[must_use]
    pub fn matches_handoff(
        &self,
        channel_binding: &[u8; 32],
        publication_public_key: &[u8; 32],
        handoff_digest: &[u8; 32],
    ) -> bool {
        self.channel.as_bytes() == *channel_binding
            && self.publication_public_key == *publication_public_key
            && self.claims.process.handoff.as_bytes() == *handoff_digest
    }

    /// Compares the signed process measurements to live native observations.
    #[must_use]
    pub fn matches_live_processes(
        &self,
        writer_start: &[u8; 32],
        writer_image: &[u8; 32],
        daemon_start: &[u8; 32],
        daemon_image: &[u8; 32],
    ) -> bool {
        self.claims.process.writer_start.as_bytes() == *writer_start
            && self.claims.process.writer_image.as_bytes() == *writer_image
            && self.claims.process.daemon_start.as_bytes() == *daemon_start
            && self.claims.process.daemon_image.as_bytes() == *daemon_image
    }

    /// Compares only the signed WRITER process facts to live self-measure;
    /// daemon-identity facts are accepted from the signature itself.
    #[must_use]
    pub fn matches_writer_live_facts(
        &self,
        writer_start: &[u8; 32],
        writer_image: &[u8; 32],
    ) -> bool {
        self.claims.process.writer_start.as_bytes() == *writer_start
            && self.claims.process.writer_image.as_bytes() == *writer_image
    }

    /// Returns the SIGNATURE-bound release tuple as a fact (not an
    /// expectation); callers with an independently retained tuple compare it
    /// at their own trust boundary.
    #[must_use]
    pub fn attested_release_tuple(&self) -> crate::credential::enrollment::CredentialBindingDigest {
        self.claims.runtime.release_tuple
    }

    /// Projects the signed release tuple as an opaque equality matcher.
    #[must_use]
    pub fn release_binding_expectation(&self) -> runne_domain::DigestEqualityMatcherV1 {
        runne_domain::DigestEqualityMatcherV1::from_expected(
            self.claims.runtime.release_tuple.as_bytes(),
        )
    }

    /// Checks the signed one-shot window against the local wall clock.
    #[must_use]
    pub fn is_current_now(&self) -> bool {
        let Ok(elapsed) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
            return false;
        };
        let Ok(now) = i64::try_from(elapsed.as_secs()) else {
            return false;
        };
        self.claims.ticket.issued_at <= now && now < self.claims.ticket.expires_at
    }
}
