use crate::{CredentialVersionRef, ProviderId};

use super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialOperationAction,
    CredentialOperationId, CredentialOperationMetadata, CredentialOperationState,
    CredentialReadinessRevision, CredentialTerminalDisposition,
};

mod validation;

/// Immutable durable view of one credential enrollment operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialOperationSnapshot {
    operation_id: CredentialOperationId,
    provider_id: ProviderId,
    action: CredentialOperationAction,
    state: CredentialOperationState,
    allocated_credential_version: Option<CredentialVersionRef>,
    target_credential_version: Option<CredentialVersionRef>,
    metadata: CredentialOperationMetadata,
}

impl CredentialOperationSnapshot {
    /// Validates provider/version identity and v24 replay/tombstone metadata.
    pub fn new(
        operation_id: CredentialOperationId,
        provider_id: ProviderId,
        action: CredentialOperationAction,
        state: CredentialOperationState,
        allocated_credential_version: Option<CredentialVersionRef>,
        target_credential_version: Option<CredentialVersionRef>,
        metadata: CredentialOperationMetadata,
    ) -> Result<Self, CredentialEnrollmentError> {
        if [
            allocated_credential_version.as_ref(),
            target_credential_version.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|version| version.provider() != &provider_id)
            || !validation::valid_snapshot_shape(
                action,
                state,
                allocated_credential_version.as_ref(),
                target_credential_version.as_ref(),
                &metadata,
            )
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            operation_id,
            provider_id,
            action,
            state,
            allocated_credential_version,
            target_credential_version,
            metadata,
        })
    }
    /// Returns the durable operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the provider identity.
    pub const fn provider(&self) -> &ProviderId {
        &self.provider_id
    }
    /// Returns the operation action.
    pub const fn action(&self) -> CredentialOperationAction {
        self.action
    }
    /// Returns the authoritative operation state.
    pub const fn state(&self) -> CredentialOperationState {
        self.state
    }
    /// Returns the allocated version when this operation has one.
    pub const fn allocated_credential_version(&self) -> Option<&CredentialVersionRef> {
        self.allocated_credential_version.as_ref()
    }
    /// Returns the immutable destructive-operation target, when present.
    pub const fn target_credential_version(&self) -> Option<&CredentialVersionRef> {
        self.target_credential_version.as_ref()
    }
    /// Returns all immutable safe durable metadata.
    pub const fn metadata(&self) -> &CredentialOperationMetadata {
        &self.metadata
    }
    /// Returns the immutable exact installation owner binding.
    pub const fn installation_owner_id(&self) -> CredentialInstallationOwnerId {
        self.metadata.installation_owner_id()
    }
    /// Returns the accepted begin proof digest.
    pub const fn begin_proof_digest(&self) -> CredentialBindingDigest {
        self.metadata.begin_proof_digest()
    }
    /// Returns the accepted continuation digest after claim.
    pub const fn continuation_binding_digest(&self) -> Option<CredentialBindingDigest> {
        self.metadata.continuation_binding_digest()
    }
    /// Returns the full process/release binding digest after claim.
    pub const fn process_release_binding_digest(&self) -> Option<CredentialBindingDigest> {
        self.metadata.process_release_binding_digest()
    }
    /// Returns the safe terminal disposition.
    pub const fn terminal_disposition(&self) -> Option<CredentialTerminalDisposition> {
        self.metadata.terminal_disposition()
    }
    /// Returns the permanent tombstone digest.
    pub const fn tombstone_digest(&self) -> Option<CredentialBindingDigest> {
        self.metadata.tombstone_digest()
    }
    /// Returns the expected lifecycle revision.
    pub const fn lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.metadata.expected_lifecycle_revision()
    }
    /// Returns the expected provider fence.
    pub const fn fence(&self) -> CredentialFence {
        self.metadata.expected_prior_fence()
    }
}

/// Immutable provider lifecycle view used by callers after lifecycle CAS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialLifecycleSnapshot {
    provider_id: ProviderId,
    active_version: Option<CredentialVersionRef>,
    lifecycle_revision: CredentialLifecycleRevision,
    fence: CredentialFence,
    readiness_revision: CredentialReadinessRevision,
    next_credential_version: u64,
}

impl CredentialLifecycleSnapshot {
    /// Validates that an optional active version belongs to the provider.
    pub fn new(
        provider_id: ProviderId,
        active_version: Option<CredentialVersionRef>,
        lifecycle_revision: CredentialLifecycleRevision,
        fence: CredentialFence,
        readiness_revision: CredentialReadinessRevision,
        next_credential_version: u64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if active_version
            .as_ref()
            .is_some_and(|version| version.provider() != &provider_id)
            || next_credential_version == 0
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            provider_id,
            active_version,
            lifecycle_revision,
            fence,
            readiness_revision,
            next_credential_version,
        })
    }
    /// Returns the provider identity.
    pub const fn provider(&self) -> &ProviderId {
        &self.provider_id
    }
    /// Returns the active credential version, when one exists.
    pub const fn active_version(&self) -> Option<&CredentialVersionRef> {
        self.active_version.as_ref()
    }
    /// Returns the authoritative lifecycle revision.
    pub const fn lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.lifecycle_revision
    }
    /// Returns the authoritative provider fence.
    pub const fn fence(&self) -> CredentialFence {
        self.fence
    }
    /// Returns the authoritative readiness revision.
    pub const fn readiness_revision(&self) -> CredentialReadinessRevision {
        self.readiness_revision
    }
    /// Returns the next provider-local monotonic version allocation.
    pub const fn next_credential_version(&self) -> u64 {
        self.next_credential_version
    }
}

/// Recovery work for a non-terminal operation requiring reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecoveryWork {
    operation: CredentialOperationSnapshot,
}

impl CredentialRecoveryWork {
    /// Accepts only post-claim operations that may require reconciliation.
    pub fn new(operation: CredentialOperationSnapshot) -> Result<Self, CredentialEnrollmentError> {
        if !matches!(
            operation.state(),
            CredentialOperationState::Claimed
                | CredentialOperationState::NativeEffectObserved
                | CredentialOperationState::ReadbackVerified
        ) {
            return Err(CredentialEnrollmentError::InvalidTransition);
        }
        Ok(Self { operation })
    }
    /// Returns the immutable operation snapshot.
    pub const fn operation(&self) -> &CredentialOperationSnapshot {
        &self.operation
    }
}

/// Provider-wide hard-fence request with a strictly advancing fence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardFenceProvider {
    provider_id: ProviderId,
    expected_prior_fence: CredentialFence,
    new_fence: CredentialFence,
}

impl HardFenceProvider {
    /// Validates a strictly monotonic provider fence advance.
    pub fn new(
        provider_id: ProviderId,
        expected_prior_fence: CredentialFence,
        new_fence: CredentialFence,
    ) -> Result<Self, CredentialEnrollmentError> {
        if new_fence <= expected_prior_fence {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            provider_id,
            expected_prior_fence,
            new_fence,
        })
    }
    /// Returns the provider identity.
    pub const fn provider(&self) -> &ProviderId {
        &self.provider_id
    }
    /// Returns the compare-and-set prior fence.
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.expected_prior_fence
    }
    /// Returns the requested successor fence.
    pub const fn new_fence(&self) -> CredentialFence {
        self.new_fence
    }
}
