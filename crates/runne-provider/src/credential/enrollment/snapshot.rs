use crate::{CredentialVersionRef, ProviderId};

use super::{
    CredentialEnrollmentError, CredentialFence, CredentialLifecycleRevision,
    CredentialOperationAction, CredentialOperationId, CredentialOperationState,
};

/// Immutable durable view of one credential enrollment operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialOperationSnapshot {
    operation_id: CredentialOperationId,
    provider_id: ProviderId,
    action: CredentialOperationAction,
    state: CredentialOperationState,
    credential_version: CredentialVersionRef,
    lifecycle_revision: CredentialLifecycleRevision,
    fence: CredentialFence,
}

impl CredentialOperationSnapshot {
    /// Validates the provider/version binding of a durable operation view.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: CredentialOperationId,
        provider_id: ProviderId,
        action: CredentialOperationAction,
        state: CredentialOperationState,
        credential_version: CredentialVersionRef,
        lifecycle_revision: CredentialLifecycleRevision,
        fence: CredentialFence,
    ) -> Result<Self, CredentialEnrollmentError> {
        if credential_version.provider() != &provider_id {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            operation_id,
            provider_id,
            action,
            state,
            credential_version,
            lifecycle_revision,
            fence,
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

    /// Returns the target credential version.
    pub const fn credential_version(&self) -> &CredentialVersionRef {
        &self.credential_version
    }

    /// Returns the lifecycle revision observed with the operation.
    pub const fn lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.lifecycle_revision
    }

    /// Returns the provider fence observed with the operation.
    pub const fn fence(&self) -> CredentialFence {
        self.fence
    }
}

/// Immutable provider lifecycle view used by callers after lifecycle CAS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialLifecycleSnapshot {
    provider_id: ProviderId,
    active_version: Option<CredentialVersionRef>,
    lifecycle_revision: CredentialLifecycleRevision,
    fence: CredentialFence,
}

impl CredentialLifecycleSnapshot {
    /// Validates that an optional active version belongs to the provider.
    pub fn new(
        provider_id: ProviderId,
        active_version: Option<CredentialVersionRef>,
        lifecycle_revision: CredentialLifecycleRevision,
        fence: CredentialFence,
    ) -> Result<Self, CredentialEnrollmentError> {
        if active_version
            .as_ref()
            .is_some_and(|version| version.provider() != &provider_id)
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            provider_id,
            active_version,
            lifecycle_revision,
            fence,
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
