use sha2::{Digest, Sha256};

use super::{CredentialProcessBinding, push};
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationId,
};

const MIGRATION_BINDING_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_RELEASE_MIGRATION_BINDING_V2\0";

/// Phase of an N-to-N+1 writer identity migration.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterIdentityMigrationPhase {
    /// Old writer performs its final native effect.
    OldWriterEffect = 1,
    /// New writer independently verifies the resulting state.
    NewWriterVerify = 2,
}

/// Exact migration snapshot with phase-specific live process evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialReleaseMigrationBinding {
    migration_id: CredentialOperationId,
    phase: WriterIdentityMigrationPhase,
    old_candidate_and_manifest: CredentialBindingDigest,
    new_candidate_and_manifest: CredentialBindingDigest,
    old_desktop_writer_reader_contract: CredentialBindingDigest,
    new_desktop_writer_reader_contract: CredentialBindingDigest,
    database_generation: u64,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
    live_process: CredentialProcessBinding,
}

impl CredentialReleaseMigrationBinding {
    /// Constructs one phase and rejects a non-migration N-to-N tuple.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        migration_id: CredentialOperationId,
        phase: WriterIdentityMigrationPhase,
        old_candidate_and_manifest: CredentialBindingDigest,
        new_candidate_and_manifest: CredentialBindingDigest,
        old_desktop_writer_reader_contract: CredentialBindingDigest,
        new_desktop_writer_reader_contract: CredentialBindingDigest,
        database_generation: u64,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
        live_process: CredentialProcessBinding,
    ) -> Result<Self, CredentialEnrollmentError> {
        if database_generation == 0
            || (old_candidate_and_manifest == new_candidate_and_manifest
                && old_desktop_writer_reader_contract == new_desktop_writer_reader_contract)
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            migration_id,
            phase,
            old_candidate_and_manifest,
            new_candidate_and_manifest,
            old_desktop_writer_reader_contract,
            new_desktop_writer_reader_contract,
            database_generation,
            expected_lifecycle_revision,
            expected_prior_fence,
            live_process,
        })
    }

    /// Rejects different authoritative snapshots, same phase, or same live process.
    pub fn validates_counterpart(&self, other: &Self) -> Result<(), CredentialEnrollmentError> {
        if self.migration_id != other.migration_id
            || self.phase == other.phase
            || self.old_candidate_and_manifest != other.old_candidate_and_manifest
            || self.new_candidate_and_manifest != other.new_candidate_and_manifest
            || self.old_desktop_writer_reader_contract != other.old_desktop_writer_reader_contract
            || self.new_desktop_writer_reader_contract != other.new_desktop_writer_reader_contract
            || self.database_generation != other.database_generation
            || self.expected_lifecycle_revision != other.expected_lifecycle_revision
            || self.expected_prior_fence != other.expected_prior_fence
            || self.live_process == other.live_process
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(())
    }

    /// Hashes the phase and exact authoritative snapshot under a distinct domain.
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
        push(&mut hasher, &self.live_process.start_identity().as_bytes());
        push(
            &mut hasher,
            &self.live_process.retained_handle_digest().as_bytes(),
        );
        CredentialBindingDigest::from_measured(hasher.finalize().into())
            .expect("SHA-256 is non-zero")
    }
}
