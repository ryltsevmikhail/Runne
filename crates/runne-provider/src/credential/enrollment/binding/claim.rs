use sha2::{Digest, Sha256};

use crate::{CredentialVersionRef, ProviderId};

use super::{CredentialMeasurementSnapshot, push};
use crate::credential::enrollment::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt,
};

const CLAIM_BINDING_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_CLAIM_BINDING_V2\0";

/// Immutable complete claim binding for exactly one live writer process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialClaimBinding {
    candidate_source_identity: CredentialBindingDigest,
    release_manifest_digest: CredentialBindingDigest,
    desktop_executable_identity: CredentialBindingDigest,
    writer_executable_identity: CredentialBindingDigest,
    reader_executable_identity: CredentialBindingDigest,
    contract_bundle_digest: CredentialBindingDigest,
    daemon_authority_id: CredentialBindingDigest,
    database_generation: u64,
    protected_session_id: CredentialBindingDigest,
    desktop_supervisor_generation: u64,
    writer_launch_id: CredentialBindingDigest,
    writer_process_start_identity: CredentialBindingDigest,
    writer_process_handle_identity: CredentialBindingDigest,
    broker_channel_binding: CredentialBindingDigest,
    continuation_binding_digest: CredentialBindingDigest,
    operation_id: CredentialOperationId,
    ticket_attempt: CredentialTicketAttempt,
    ticket_digest: CredentialBindingDigest,
    provider_id: ProviderId,
    action: CredentialOperationAction,
    credential_version: CredentialVersionRef,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
    issued_at_high_water: i64,
    expires_at_high_water: i64,
}

impl CredentialClaimBinding {
    /// Constructs a claim only from source-separated measurements and validated operation data.
    pub fn new(
        measurements: CredentialMeasurementSnapshot,
        claim: ClaimCredentialOperation,
    ) -> Result<Self, CredentialEnrollmentError> {
        let [
            candidate_source_identity,
            release_manifest_digest,
            desktop_executable_identity,
            writer_executable_identity,
            reader_executable_identity,
            contract_bundle_digest,
            daemon_authority_id,
            protected_session_id,
            writer_launch_id,
            writer_process_start_identity,
            writer_process_handle_identity,
            broker_channel_binding,
            continuation_binding_digest,
        ] = measurements.digests();
        Ok(Self {
            candidate_source_identity,
            release_manifest_digest,
            desktop_executable_identity,
            writer_executable_identity,
            reader_executable_identity,
            contract_bundle_digest,
            daemon_authority_id,
            database_generation: claim.database_generation(),
            protected_session_id,
            desktop_supervisor_generation: claim.desktop_supervisor_generation(),
            writer_launch_id,
            writer_process_start_identity,
            writer_process_handle_identity,
            broker_channel_binding,
            continuation_binding_digest,
            operation_id: claim.operation_id(),
            ticket_attempt: claim.ticket_attempt(),
            ticket_digest: claim.ticket_digest(),
            provider_id: claim.provider_id().clone(),
            action: claim.action(),
            credential_version: claim.credential_version().clone(),
            expected_lifecycle_revision: claim.expected_lifecycle_revision(),
            expected_prior_fence: claim.expected_prior_fence(),
            issued_at_high_water: claim.issued_at_high_water(),
            expires_at_high_water: claim.expires_at_high_water(),
        })
    }

    /// Returns the durable operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the exact provider identity.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
    /// Returns the closed operation action.
    pub const fn action(&self) -> CredentialOperationAction {
        self.action
    }
    /// Returns the exact target credential version.
    pub const fn credential_version(&self) -> &CredentialVersionRef {
        &self.credential_version
    }

    /// Hashes every stored field in canonical declaration order with length prefixes.
    pub fn digest(&self) -> CredentialBindingDigest {
        let mut hasher = Sha256::new();
        push(&mut hasher, CLAIM_BINDING_DOMAIN);
        for value in [
            self.candidate_source_identity,
            self.release_manifest_digest,
            self.desktop_executable_identity,
            self.writer_executable_identity,
            self.reader_executable_identity,
            self.contract_bundle_digest,
            self.daemon_authority_id,
        ] {
            push(&mut hasher, &value.as_bytes());
        }
        push(&mut hasher, &self.database_generation.to_be_bytes());
        push(&mut hasher, &self.protected_session_id.as_bytes());
        push(
            &mut hasher,
            &self.desktop_supervisor_generation.to_be_bytes(),
        );
        for value in [
            self.writer_launch_id,
            self.writer_process_start_identity,
            self.writer_process_handle_identity,
            self.broker_channel_binding,
            self.continuation_binding_digest,
        ] {
            push(&mut hasher, &value.as_bytes());
        }
        push(&mut hasher, &self.operation_id.bytes());
        push(&mut hasher, &self.ticket_attempt.get().to_be_bytes());
        push(&mut hasher, &self.ticket_digest.as_bytes());
        push(&mut hasher, self.provider_id.as_str().as_bytes());
        push(&mut hasher, &[self.action as u8]);
        push(
            &mut hasher,
            self.credential_version.provider().as_str().as_bytes(),
        );
        push(
            &mut hasher,
            &self.credential_version.version().to_be_bytes(),
        );
        push(&mut hasher, self.credential_version.ref_digest());
        push(
            &mut hasher,
            &self.expected_lifecycle_revision.get().to_be_bytes(),
        );
        push(&mut hasher, &self.expected_prior_fence.get().to_be_bytes());
        push(&mut hasher, &self.issued_at_high_water.to_be_bytes());
        push(&mut hasher, &self.expires_at_high_water.to_be_bytes());
        CredentialBindingDigest::from_measured(hasher.finalize().into())
            .expect("SHA-256 is non-zero")
    }
}

#[cfg(test)]
#[path = "claim/tests.rs"]
mod tests;
