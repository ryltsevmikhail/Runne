use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::{CredentialProcessBinding, push};
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationId, authority::EnrollmentAuthoritySeal,
};

const MIGRATION_BINDING_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_RELEASE_MIGRATION_BINDING_V2\0";
const OLD_TUPLE_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_RELEASE_MIGRATION_OLD_TUPLE_V2\0";
const NEW_TUPLE_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_RELEASE_MIGRATION_NEW_TUPLE_V2\0";

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
///
/// ```compile_fail
/// use runne_provider::CredentialReleaseMigrationBinding;
/// let _ = CredentialReleaseMigrationBinding::new;
/// ```
#[derive(Clone, Debug)]
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
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl PartialEq for CredentialReleaseMigrationBinding {
    fn eq(&self, other: &Self) -> bool {
        self.migration_id == other.migration_id
            && self.phase == other.phase
            && self.old_candidate_and_manifest == other.old_candidate_and_manifest
            && self.new_candidate_and_manifest == other.new_candidate_and_manifest
            && self.old_desktop_writer_reader_contract == other.old_desktop_writer_reader_contract
            && self.new_desktop_writer_reader_contract == other.new_desktop_writer_reader_contract
            && self.database_generation == other.database_generation
            && self.expected_lifecycle_revision == other.expected_lifecycle_revision
            && self.expected_prior_fence == other.expected_prior_fence
            && self.live_process == other.live_process
            && Arc::ptr_eq(&self.seal, &other.seal)
    }
}

impl Eq for CredentialReleaseMigrationBinding {}

impl CredentialReleaseMigrationBinding {
    /// Seals one phase from same-pair process evidence and rejects a non-migration N-to-N tuple.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
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
        if !live_process.belongs_to(&seal) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
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
            seal,
        })
    }

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }

    /// Returns the linked migration identity.
    pub const fn migration_id(&self) -> CredentialOperationId {
        self.migration_id
    }

    /// Returns the phase-specific writer role.
    pub const fn phase(&self) -> WriterIdentityMigrationPhase {
        self.phase
    }

    /// Returns the canonical old-release tuple digest.
    pub fn old_tuple_digest(&self) -> CredentialBindingDigest {
        tuple_digest(
            OLD_TUPLE_DOMAIN,
            self.old_candidate_and_manifest,
            self.old_desktop_writer_reader_contract,
        )
    }

    /// Returns the canonical new-release tuple digest.
    pub fn new_tuple_digest(&self) -> CredentialBindingDigest {
        tuple_digest(
            NEW_TUPLE_DOMAIN,
            self.new_candidate_and_manifest,
            self.new_desktop_writer_reader_contract,
        )
    }

    /// Rejects different authoritative snapshots, same phase, or same live process.
    pub fn validates_counterpart(&self, other: &Self) -> Result<(), CredentialEnrollmentError> {
        if !Arc::ptr_eq(&self.seal, &other.seal) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
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

fn tuple_digest(
    domain: &[u8],
    candidate_and_manifest: CredentialBindingDigest,
    desktop_writer_reader_contract: CredentialBindingDigest,
) -> CredentialBindingDigest {
    let mut hasher = Sha256::new();
    push(&mut hasher, domain);
    push(&mut hasher, &candidate_and_manifest.as_bytes());
    push(&mut hasher, &desktop_writer_reader_contract.as_bytes());
    CredentialBindingDigest::from_measured(hasher.finalize().into()).expect("SHA-256 is non-zero")
}
