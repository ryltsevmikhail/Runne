use sha2::{Digest, Sha256};

use crate::{CredentialVersionRef, ProviderId};

use super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt,
};

const CLAIM_BINDING_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_CLAIM_BINDING_V2\0";
const MIGRATION_BINDING_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_RELEASE_MIGRATION_BINDING_V2\0";

/// Independently measured live writer process identity; paths and PIDs are absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialProcessBinding {
    /// OS-native start identity for the retained child process.
    pub start_identity: CredentialBindingDigest,
    /// Digest of the retained native process handle identity.
    pub retained_handle_digest: CredentialBindingDigest,
}

impl CredentialProcessBinding {
    /// Combines separately measured start and retained-handle identities.
    pub const fn new(
        start_identity: CredentialBindingDigest,
        retained_handle_digest: CredentialBindingDigest,
    ) -> Self {
        Self {
            start_identity,
            retained_handle_digest,
        }
    }
}

/// Immutable complete claim binding for exactly one live writer process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialClaimBinding {
    /// Measured candidate source identity.
    pub candidate_source_identity: CredentialBindingDigest,
    /// Measured release manifest digest.
    pub release_manifest_digest: CredentialBindingDigest,
    /// Measured desktop executable identity.
    pub desktop_executable_identity: CredentialBindingDigest,
    /// Measured writer executable identity.
    pub writer_executable_identity: CredentialBindingDigest,
    /// Measured reader executable identity.
    pub reader_executable_identity: CredentialBindingDigest,
    /// Measured contract bundle digest.
    pub contract_bundle_digest: CredentialBindingDigest,
    /// Measured daemon authority identity.
    pub daemon_authority_id: CredentialBindingDigest,
    /// Exact database generation.
    pub database_generation: u64,
    /// Measured protected-session identity.
    pub protected_session_id: CredentialBindingDigest,
    /// Exact desktop supervisor generation.
    pub desktop_supervisor_generation: u64,
    /// Measured writer launch identity.
    pub writer_launch_id: CredentialBindingDigest,
    /// OS-native writer process start identity.
    pub writer_process_start_identity: CredentialBindingDigest,
    /// Retained writer process handle identity.
    pub writer_process_handle_identity: CredentialBindingDigest,
    /// Measured broker channel binding.
    pub broker_channel_binding: CredentialBindingDigest,
    /// Accepted one-use continuation proof digest.
    pub continuation_binding_digest: CredentialBindingDigest,
    /// Exact durable operation identity.
    pub operation_id: CredentialOperationId,
    /// Exact one-shot ticket attempt.
    pub ticket_attempt: CredentialTicketAttempt,
    /// Domain-separated raw-ticket digest.
    pub ticket_digest: CredentialBindingDigest,
    /// Exact provider identity.
    pub provider_id: ProviderId,
    /// Closed operation action.
    pub action: CredentialOperationAction,
    /// Exact immutable credential version.
    pub credential_version: CredentialVersionRef,
    /// Expected lifecycle revision.
    pub expected_lifecycle_revision: CredentialLifecycleRevision,
    /// Expected prior provider fence.
    pub expected_prior_fence: CredentialFence,
    /// Monotonic issue timestamp.
    pub issued_at_high_water: i64,
    /// Monotonic expiry timestamp.
    pub expires_at_high_water: i64,
}

impl CredentialClaimBinding {
    /// Hashes every field in declaration order with explicit byte lengths.
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

/// Phase of an N-to-N+1 writer identity migration.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterIdentityMigrationPhase {
    /// Old writer performs its final native effect.
    OldWriterEffect = 1,
    /// New writer independently verifies the resulting state.
    NewWriterVerify = 2,
}

/// Migration binding with phase-specific live process evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialReleaseMigrationBinding {
    /// Shared durable migration identity.
    pub migration_id: CredentialOperationId,
    /// Exactly one migration phase.
    pub phase: WriterIdentityMigrationPhase,
    /// Exact old candidate/manifest tuple digest.
    pub old_candidate_and_manifest: CredentialBindingDigest,
    /// Exact new candidate/manifest tuple digest.
    pub new_candidate_and_manifest: CredentialBindingDigest,
    /// Exact old desktop/writer/reader/contract tuple digest.
    pub old_desktop_writer_reader_contract: CredentialBindingDigest,
    /// Exact new desktop/writer/reader/contract tuple digest.
    pub new_desktop_writer_reader_contract: CredentialBindingDigest,
    /// Exact database generation.
    pub database_generation: u64,
    /// Expected lifecycle revision.
    pub expected_lifecycle_revision: CredentialLifecycleRevision,
    /// Expected provider fence.
    pub expected_prior_fence: CredentialFence,
    /// Live process evidence bound to this phase.
    pub live_process: CredentialProcessBinding,
}

impl CredentialReleaseMigrationBinding {
    /// Rejects equal process evidence when pairing the two required phases.
    pub fn validates_counterpart(&self, other: &Self) -> Result<(), CredentialEnrollmentError> {
        if self.migration_id != other.migration_id
            || self.phase == other.phase
            || self.old_candidate_and_manifest != other.old_candidate_and_manifest
            || self.new_candidate_and_manifest != other.new_candidate_and_manifest
            || self.old_desktop_writer_reader_contract != other.old_desktop_writer_reader_contract
            || self.new_desktop_writer_reader_contract != other.new_desktop_writer_reader_contract
            || self.live_process == other.live_process
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(())
    }

    /// Hashes the phase and phase-specific live process under a distinct domain.
    pub fn digest(&self) -> CredentialBindingDigest {
        let mut hasher = Sha256::new();
        push(&mut hasher, MIGRATION_BINDING_DOMAIN);
        push(&mut hasher, &self.migration_id.bytes());
        push(&mut hasher, &[self.phase as u8]);
        for value in [
            self.old_candidate_and_manifest,
            self.new_candidate_and_manifest,
            self.old_desktop_writer_reader_contract,
            self.new_desktop_writer_reader_contract,
        ] {
            push(&mut hasher, &value.as_bytes());
        }
        push(&mut hasher, &self.database_generation.to_be_bytes());
        push(
            &mut hasher,
            &self.expected_lifecycle_revision.get().to_be_bytes(),
        );
        push(&mut hasher, &self.expected_prior_fence.get().to_be_bytes());
        push(&mut hasher, &self.live_process.start_identity.as_bytes());
        push(
            &mut hasher,
            &self.live_process.retained_handle_digest.as_bytes(),
        );
        CredentialBindingDigest::from_measured(hasher.finalize().into())
            .expect("SHA-256 is non-zero")
    }
}

fn push(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}
