use std::sync::Arc;

use super::super::{
    CredentialBindingDigest, CredentialOperationId, WriterIdentityMigrationPhase,
    authority::EnrollmentAuthoritySeal,
};

/// Immutable migration fields persisted for a linked writer-identity operation.
///
/// ```compile_fail
/// use runne_provider::CredentialMigrationMetadata;
/// let _ = CredentialMigrationMetadata::new;
/// ```
#[derive(Clone, Debug)]
pub struct CredentialMigrationMetadata {
    migration_id: CredentialOperationId,
    phase: WriterIdentityMigrationPhase,
    old_tuple_digest: CredentialBindingDigest,
    new_tuple_digest: CredentialBindingDigest,
    binding_digest: CredentialBindingDigest,
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl PartialEq for CredentialMigrationMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.migration_id == other.migration_id
            && self.phase == other.phase
            && self.old_tuple_digest == other.old_tuple_digest
            && self.new_tuple_digest == other.new_tuple_digest
            && self.binding_digest == other.binding_digest
            && Arc::ptr_eq(&self.seal, &other.seal)
    }
}

impl Eq for CredentialMigrationMetadata {}

impl CredentialMigrationMetadata {
    /// Captures the safe digest-only fields required by the v24 migration columns.
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        migration_id: CredentialOperationId,
        phase: WriterIdentityMigrationPhase,
        old_tuple_digest: CredentialBindingDigest,
        new_tuple_digest: CredentialBindingDigest,
        binding_digest: CredentialBindingDigest,
    ) -> Self {
        Self {
            migration_id,
            phase,
            old_tuple_digest,
            new_tuple_digest,
            binding_digest,
            seal,
        }
    }

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }

    /// Returns the linked migration identity.
    pub const fn migration_id(&self) -> CredentialOperationId {
        self.migration_id
    }

    /// Returns the closed migration phase.
    pub const fn phase(&self) -> WriterIdentityMigrationPhase {
        self.phase
    }

    /// Returns the old release tuple digest.
    pub const fn old_tuple_digest(&self) -> CredentialBindingDigest {
        self.old_tuple_digest
    }

    /// Returns the new release tuple digest.
    pub const fn new_tuple_digest(&self) -> CredentialBindingDigest {
        self.new_tuple_digest
    }

    /// Returns the immutable broker migration binding digest.
    pub const fn binding_digest(&self) -> CredentialBindingDigest {
        self.binding_digest
    }
}
