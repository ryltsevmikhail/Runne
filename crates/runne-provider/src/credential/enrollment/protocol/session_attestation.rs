use ring::{
    rand::{SecureRandom as _, SystemRandom},
    signature,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::secret::DaemonCredentialSecretPublicationSigner;
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialInstallationOwnerId,
    CredentialOperationId, CredentialTicketAttempt,
};

mod codec;
#[cfg(any(test, feature = "test-support"))]
mod fixture;
mod issue_ticket;

pub use codec::CredentialWriterSessionAttestationCodec;
#[cfg(any(test, feature = "test-support"))]
pub(super) use fixture::attested_publication_signer_for_test;
pub use issue_ticket::CredentialIssueTicketBindingV1;

const BINDING_DOMAIN: &[u8] = b"GOCODE_VERIFIED_WRITER_SESSION_V1\0";

/// Exact ticket and durable-operation facts signed for one writer session.
#[derive(Eq, PartialEq)]
pub struct CredentialWriterSessionTicketClaimsV1 {
    operation: CredentialOperationId,
    attempt: CredentialTicketAttempt,
    issue_ticket: CredentialIssueTicketBindingV1,
    claim: CredentialBindingDigest,
    owner: CredentialInstallationOwnerId,
    begin_proof: CredentialBindingDigest,
    issued_at: i64,
    expires_at: i64,
}

impl CredentialWriterSessionTicketClaimsV1 {
    /// Validates the one-shot ticket time window before signing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: CredentialOperationId,
        attempt: CredentialTicketAttempt,
        issue_ticket: CredentialIssueTicketBindingV1,
        claim: CredentialBindingDigest,
        owner: CredentialInstallationOwnerId,
        begin_proof: CredentialBindingDigest,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !issue_ticket.matches_claims(operation, attempt, claim)
            || issued_at <= 0
            || expires_at <= issued_at
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(Self {
            operation,
            attempt,
            issue_ticket,
            claim,
            owner,
            begin_proof,
            issued_at,
            expires_at,
        })
    }
}

/// Protected-runtime facts signed for one writer session.
#[derive(Eq, PartialEq)]
pub struct CredentialWriterSessionRuntimeClaimsV1 {
    protected_session: CredentialBindingDigest,
    tauri_peer: CredentialBindingDigest,
    daemon_authority: CredentialBindingDigest,
    database_generation: u64,
    supervisor_generation: u64,
    release_tuple: CredentialBindingDigest,
}

impl CredentialWriterSessionRuntimeClaimsV1 {
    /// Rejects absent durable generations.
    pub fn new(
        protected_session: CredentialBindingDigest,
        tauri_peer: CredentialBindingDigest,
        daemon_authority: CredentialBindingDigest,
        database_generation: u64,
        supervisor_generation: u64,
        release_tuple: CredentialBindingDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        if database_generation == 0 || supervisor_generation == 0 {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(Self {
            protected_session,
            tauri_peer,
            daemon_authority,
            database_generation,
            supervisor_generation,
            release_tuple,
        })
    }
}

/// Exact handoff and live-process facts signed for one writer session.
#[derive(Eq, PartialEq)]
pub struct CredentialWriterSessionProcessClaimsV1 {
    handoff: CredentialBindingDigest,
    writer_start: CredentialBindingDigest,
    writer_image: CredentialBindingDigest,
    writer_ownership: CredentialBindingDigest,
    daemon_start: CredentialBindingDigest,
    daemon_image: CredentialBindingDigest,
}

impl CredentialWriterSessionProcessClaimsV1 {
    /// Collects already validated nonzero process digests.
    pub const fn new(
        handoff: CredentialBindingDigest,
        writer_start: CredentialBindingDigest,
        writer_image: CredentialBindingDigest,
        writer_ownership: CredentialBindingDigest,
        daemon_start: CredentialBindingDigest,
        daemon_image: CredentialBindingDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        Ok(Self {
            handoff,
            writer_start,
            writer_image,
            writer_ownership,
            daemon_start,
            daemon_image,
        })
    }
}

/// Validated inert input consumed by the daemon session signer.
pub struct CredentialWriterSessionAttestationClaimsV1 {
    ticket: CredentialWriterSessionTicketClaimsV1,
    runtime: CredentialWriterSessionRuntimeClaimsV1,
    process: CredentialWriterSessionProcessClaimsV1,
}

impl CredentialWriterSessionAttestationClaimsV1 {
    /// Joins independently validated claim groups without minting authority.
    #[must_use]
    pub const fn new(
        ticket: CredentialWriterSessionTicketClaimsV1,
        runtime: CredentialWriterSessionRuntimeClaimsV1,
        process: CredentialWriterSessionProcessClaimsV1,
    ) -> Self {
        Self {
            ticket,
            runtime,
            process,
        }
    }
}

/// Inert signed session record; decoding it grants no writer authority.
pub struct SignedCredentialWriterSessionAttestationV1 {
    claims: CredentialWriterSessionAttestationClaimsV1,
    channel: CredentialBindingDigest,
    publication_public_key: [u8; 32],
    signature: [u8; 64],
}

impl SignedCredentialWriterSessionAttestationV1 {
    /// Returns a non-authoritative digest of the exact signed record.
    pub fn binding_digest(&self) -> CredentialBindingDigest {
        let mut hasher = Sha256::new();
        hasher.update(BINDING_DOMAIN);
        hasher.update(CredentialWriterSessionAttestationCodec::encode(self));
        CredentialBindingDigest::from_measured(hasher.finalize().into())
            .expect("SHA-256 is non-zero")
    }

    /// Returns the attested ticket facts for exact comparison by a future verifier.
    pub const fn ticket_claims(&self) -> &CredentialWriterSessionTicketClaimsV1 {
        &self.claims.ticket
    }

    /// Returns the attested runtime facts for exact comparison by a future verifier.
    pub const fn runtime_claims(&self) -> &CredentialWriterSessionRuntimeClaimsV1 {
        &self.claims.runtime
    }

    /// Returns the attested process facts for exact comparison by a future verifier.
    pub const fn process_claims(&self) -> &CredentialWriterSessionProcessClaimsV1 {
        &self.claims.process
    }

    /// Returns the signed rendezvous channel digest.
    pub const fn channel_binding(&self) -> CredentialBindingDigest {
        self.channel
    }

    /// Returns the embedded key only as a comparison value, never as a trust root.
    pub const fn publication_public_key(&self) -> [u8; 32] {
        self.publication_public_key
    }
}

impl core::fmt::Debug for SignedCredentialWriterSessionAttestationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SignedCredentialWriterSessionAttestationV1(<inert-signed>)")
    }
}

/// Daemon-only signer state that must attest a session before publication exists.
pub struct CredentialWriterSessionAttestationSigner {
    key_pair: signature::Ed25519KeyPair,
    channel: CredentialBindingDigest,
}

impl CredentialWriterSessionAttestationSigner {
    /// Generates a fresh session-first signer bound to one nonzero channel.
    pub fn generate(channel: [u8; 32]) -> Result<Self, CredentialEnrollmentError> {
        let channel = CredentialBindingDigest::from_measured(channel)?;
        let mut seed = Zeroizing::new([0; 32]);
        SystemRandom::new()
            .fill(seed.as_mut())
            .map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?;
        let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(seed.as_ref())
            .map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?;
        Ok(Self { key_pair, channel })
    }

    /// Returns only the expected public key for the authenticated handoff.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        use ring::signature::KeyPair as _;
        self.key_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("key width")
    }

    /// Consumes the pre-attestation state and unlocks one exact publication signer.
    pub fn sign(
        self,
        claims: CredentialWriterSessionAttestationClaimsV1,
    ) -> Result<
        (
            SignedCredentialWriterSessionAttestationV1,
            DaemonCredentialSecretPublicationSigner,
        ),
        CredentialEnrollmentError,
    > {
        if claims.ticket.issue_ticket.channel() != self.channel {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let public_key = self.public_key();
        let mut record = SignedCredentialWriterSessionAttestationV1 {
            claims,
            channel: self.channel,
            publication_public_key: public_key,
            signature: [0; 64],
        };
        record.signature = self
            .key_pair
            .sign(&codec::signature_message(&record))
            .as_ref()
            .try_into()
            .expect("signature width");
        let publication = DaemonCredentialSecretPublicationSigner::after_attestation(
            self.key_pair,
            self.channel,
            record.claims.ticket.operation,
            record.claims.ticket.attempt,
            record.claims.ticket.claim,
        );
        Ok((record, publication))
    }
}
