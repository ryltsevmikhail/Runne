use std::sync::Arc;

use runne_domain::id::{CommandId, IdempotencyKey};

use super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialNativeEffectDisposition,
    CredentialOperationId, CredentialReadbackDisposition, CredentialTerminalDisposition,
    WriterIdentityMigrationPhase, authority::EnrollmentAuthoritySeal,
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
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl PartialEq for CredentialMigrationMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.migration_id == other.migration_id
            && self.phase == other.phase
            && self.old_tuple_digest == other.old_tuple_digest
            && self.new_tuple_digest == other.new_tuple_digest
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
    ) -> Self {
        Self {
            migration_id,
            phase,
            old_tuple_digest,
            new_tuple_digest,
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
}

/// Safe durable metadata for an enrollment operation snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialOperationMetadata {
    command_id: CommandId,
    idempotency_key: IdempotencyKey,
    installation_owner_id: CredentialInstallationOwnerId,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
    begin_proof_digest: CredentialBindingDigest,
    continuation_binding_digest: Option<CredentialBindingDigest>,
    process_release_binding_digest: Option<CredentialBindingDigest>,
    native_effect_disposition: Option<CredentialNativeEffectDisposition>,
    readback_disposition: Option<CredentialReadbackDisposition>,
    readback_observation_digest: Option<CredentialBindingDigest>,
    terminal_disposition: Option<CredentialTerminalDisposition>,
    migration: Option<CredentialMigrationMetadata>,
    created_at_high_water: i64,
    updated_at_high_water: i64,
    tombstone_digest: Option<CredentialBindingDigest>,
}

impl CredentialOperationMetadata {
    /// Validates immutable replay identity and monotonic operation timestamps.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command_id: CommandId,
        idempotency_key: IdempotencyKey,
        installation_owner_id: CredentialInstallationOwnerId,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
        begin_proof_digest: CredentialBindingDigest,
        created_at_high_water: i64,
        updated_at_high_water: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if created_at_high_water < 0 || updated_at_high_water < created_at_high_water {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            command_id,
            idempotency_key,
            installation_owner_id,
            expected_lifecycle_revision,
            expected_prior_fence,
            begin_proof_digest,
            continuation_binding_digest: None,
            process_release_binding_digest: None,
            native_effect_disposition: None,
            readback_disposition: None,
            readback_observation_digest: None,
            terminal_disposition: None,
            migration: None,
            created_at_high_water,
            updated_at_high_water,
            tombstone_digest: None,
        })
    }
    /// Adds the exact digests atomically consumed by a successful claim.
    pub fn with_claim(
        mut self,
        continuation: CredentialBindingDigest,
        binding: CredentialBindingDigest,
    ) -> Self {
        self.continuation_binding_digest = Some(continuation);
        self.process_release_binding_digest = Some(binding);
        self
    }
    /// Adds the safe native-effect disposition.
    pub fn with_native_effect(mut self, disposition: CredentialNativeEffectDisposition) -> Self {
        self.native_effect_disposition = Some(disposition);
        self
    }
    /// Adds one exact independent readback observation.
    pub fn with_readback(
        mut self,
        disposition: CredentialReadbackDisposition,
        digest: CredentialBindingDigest,
    ) -> Self {
        self.readback_disposition = Some(disposition);
        self.readback_observation_digest = Some(digest);
        self
    }
    /// Adds the safe terminal replay disposition.
    pub fn with_terminal(mut self, disposition: CredentialTerminalDisposition) -> Self {
        self.terminal_disposition = Some(disposition);
        self
    }
    /// Adds the linked digest-only migration tuple.
    pub fn with_migration(mut self, migration: CredentialMigrationMetadata) -> Self {
        self.migration = Some(migration);
        self
    }
    /// Adds the permanent tombstone digest.
    pub fn with_tombstone(mut self, digest: CredentialBindingDigest) -> Self {
        self.tombstone_digest = Some(digest);
        self
    }
    /// Returns the canonical command identity.
    pub const fn command_id(&self) -> CommandId {
        self.command_id
    }
    /// Returns the canonical idempotency identity.
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    /// Returns the exact immutable installation owner binding.
    pub const fn installation_owner_id(&self) -> CredentialInstallationOwnerId {
        self.installation_owner_id
    }
    /// Returns the expected lifecycle revision.
    pub const fn expected_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.expected_lifecycle_revision
    }
    /// Returns the expected credential fence.
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.expected_prior_fence
    }
    /// Returns the accepted begin proof digest.
    pub const fn begin_proof_digest(&self) -> CredentialBindingDigest {
        self.begin_proof_digest
    }
    /// Returns the accepted continuation digest after claim.
    pub const fn continuation_binding_digest(&self) -> Option<CredentialBindingDigest> {
        self.continuation_binding_digest
    }
    /// Returns the full process/release binding digest after claim.
    pub const fn process_release_binding_digest(&self) -> Option<CredentialBindingDigest> {
        self.process_release_binding_digest
    }
    /// Returns the safe native-effect disposition.
    pub const fn native_effect_disposition(&self) -> Option<CredentialNativeEffectDisposition> {
        self.native_effect_disposition
    }
    /// Returns the exact readback disposition.
    pub const fn readback_disposition(&self) -> Option<CredentialReadbackDisposition> {
        self.readback_disposition
    }
    /// Returns the exact readback observation digest.
    pub const fn readback_observation_digest(&self) -> Option<CredentialBindingDigest> {
        self.readback_observation_digest
    }
    /// Returns the safe terminal disposition.
    pub const fn terminal_disposition(&self) -> Option<CredentialTerminalDisposition> {
        self.terminal_disposition
    }
    /// Returns migration metadata for linked writer migration operations.
    pub const fn migration(&self) -> Option<&CredentialMigrationMetadata> {
        self.migration.as_ref()
    }
    /// Returns the created high-water timestamp.
    pub const fn created_at_high_water(&self) -> i64 {
        self.created_at_high_water
    }
    /// Returns the updated high-water timestamp.
    pub const fn updated_at_high_water(&self) -> i64 {
        self.updated_at_high_water
    }
    /// Returns the permanent tombstone digest.
    pub const fn tombstone_digest(&self) -> Option<CredentialBindingDigest> {
        self.tombstone_digest
    }
}

#[cfg(test)]
#[path = "operation_metadata/tests.rs"]
mod tests;
