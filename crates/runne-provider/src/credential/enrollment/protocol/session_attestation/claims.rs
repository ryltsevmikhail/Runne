use super::CredentialIssueTicketBindingV1;
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialInstallationOwnerId,
    CredentialOperationId, CredentialTicketAttempt,
};

/// Exact ticket and durable-operation facts signed for one writer session.
#[derive(Eq, PartialEq)]
pub struct CredentialWriterSessionTicketClaimsV1 {
    pub(super) operation: CredentialOperationId,
    pub(super) attempt: CredentialTicketAttempt,
    pub(super) issue_ticket: CredentialIssueTicketBindingV1,
    pub(super) claim: CredentialBindingDigest,
    pub(super) owner: CredentialInstallationOwnerId,
    pub(super) begin_proof: CredentialBindingDigest,
    pub(super) issued_at: i64,
    pub(super) expires_at: i64,
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
        let lifetime = expires_at.checked_sub(issued_at);
        if !issue_ticket.matches_claims(operation, attempt, claim)
            || issued_at <= 0
            || !matches!(lifetime, Some(1..=3_600))
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
    pub(super) protected_session: CredentialBindingDigest,
    pub(super) tauri_peer: CredentialBindingDigest,
    pub(super) daemon_authority: CredentialBindingDigest,
    pub(super) database_generation: u64,
    pub(super) supervisor_generation: u64,
    pub(super) release_tuple: CredentialBindingDigest,
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
    pub(super) handoff: CredentialBindingDigest,
    pub(super) writer_start: CredentialBindingDigest,
    pub(super) writer_image: CredentialBindingDigest,
    pub(super) writer_ownership: CredentialBindingDigest,
    pub(super) daemon_start: CredentialBindingDigest,
    pub(super) daemon_image: CredentialBindingDigest,
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
    pub(super) ticket: CredentialWriterSessionTicketClaimsV1,
    pub(super) runtime: CredentialWriterSessionRuntimeClaimsV1,
    pub(super) process: CredentialWriterSessionProcessClaimsV1,
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
