use runne_domain::id::{CommandId, IdempotencyKey};

use super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialNativeEffectDisposition,
    CredentialQualifiedReleaseTuple, CredentialReadbackDisposition, CredentialTerminalDisposition,
    CredentialTicketAttempt,
};

mod migration;

pub use migration::CredentialMigrationMetadata;

/// Safe durable metadata for an enrollment operation snapshot.
#[derive(Debug, PartialEq, Eq)]
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
    qualified_release_tuple: Option<CredentialQualifiedReleaseTuple>,
    claimed_ticket_attempt: Option<CredentialTicketAttempt>,
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
            qualified_release_tuple: None,
            claimed_ticket_attempt: None,
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
    /// Adds the sealed qualified release tuple retained for exact completion replay.
    pub(crate) fn with_qualified_release_tuple(
        mut self,
        qualified_release_tuple: CredentialQualifiedReleaseTuple,
    ) -> Self {
        self.qualified_release_tuple = Some(qualified_release_tuple);
        self
    }
    /// Adds the immutable claimed ticket attempt retained for completion replay.
    pub(crate) fn with_claimed_ticket_attempt(
        mut self,
        claimed_ticket_attempt: CredentialTicketAttempt,
    ) -> Self {
        self.claimed_ticket_attempt = Some(claimed_ticket_attempt);
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
    /// Returns the retained qualified release tuple digest.
    pub const fn qualified_release_tuple_digest(&self) -> Option<CredentialBindingDigest> {
        match self.qualified_release_tuple.as_ref() {
            Some(tuple) => Some(tuple.digest()),
            None => None,
        }
    }
    /// Returns the claimed one-use ticket attempt when the operation crossed claim.
    pub const fn claimed_ticket_attempt(&self) -> Option<CredentialTicketAttempt> {
        self.claimed_ticket_attempt
    }
}

impl Clone for CredentialOperationMetadata {
    fn clone(&self) -> Self {
        Self {
            command_id: self.command_id,
            idempotency_key: self.idempotency_key.clone(),
            installation_owner_id: self.installation_owner_id,
            expected_lifecycle_revision: self.expected_lifecycle_revision,
            expected_prior_fence: self.expected_prior_fence,
            begin_proof_digest: self.begin_proof_digest,
            continuation_binding_digest: self.continuation_binding_digest,
            process_release_binding_digest: self.process_release_binding_digest,
            native_effect_disposition: self.native_effect_disposition,
            readback_disposition: self.readback_disposition,
            readback_observation_digest: self.readback_observation_digest,
            terminal_disposition: self.terminal_disposition,
            migration: self.migration.clone(),
            created_at_high_water: self.created_at_high_water,
            updated_at_high_water: self.updated_at_high_water,
            tombstone_digest: self.tombstone_digest,
            qualified_release_tuple: self
                .qualified_release_tuple
                .as_ref()
                .map(CredentialQualifiedReleaseTuple::duplicate),
            claimed_ticket_attempt: self.claimed_ticket_attempt,
        }
    }
}

#[cfg(test)]
#[path = "operation_metadata/tests.rs"]
mod tests;
