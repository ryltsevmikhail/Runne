use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationId, CredentialOperationState,
    CredentialTransitionEvidence,
};

macro_rules! digest_command {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name {
            operation_id: CredentialOperationId,
            binding_digest: CredentialBindingDigest,
        }
        impl $name {
            /// Constructs the immutable command.
            pub const fn new(
                operation_id: CredentialOperationId,
                binding_digest: CredentialBindingDigest,
            ) -> Self {
                Self {
                    operation_id,
                    binding_digest,
                }
            }
            /// Returns the operation identity.
            pub const fn operation_id(&self) -> CredentialOperationId {
                self.operation_id
            }
            /// Returns the exact binding digest.
            pub const fn binding_digest(&self) -> CredentialBindingDigest {
                self.binding_digest
            }
        }
    };
}

digest_command!(
    ObserveNativeEffect,
    "Bound writer diagnostic that a native effect may have occurred."
);
digest_command!(
    FailCredentialOperation,
    "Exact-absence proof for a failed create or import operation."
);

/// Independent exact native readback bound to one operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindCredentialReadback {
    operation_id: CredentialOperationId,
    evidence: CredentialTransitionEvidence,
}

impl BindCredentialReadback {
    /// Accepts only exact version or exact absence readback evidence.
    pub fn new(
        operation_id: CredentialOperationId,
        evidence: CredentialTransitionEvidence,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !matches!(
            evidence,
            CredentialTransitionEvidence::ExactAbsenceReadback(_)
                | CredentialTransitionEvidence::ExactVersionReadback(_)
        ) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(Self {
            operation_id,
            evidence,
        })
    }
    /// Returns the operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the exact readback evidence.
    pub const fn evidence(&self) -> CredentialTransitionEvidence {
        self.evidence
    }
}

/// Lifecycle-CAS completion input after action-specific readback validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompleteCredentialOperation {
    operation_id: CredentialOperationId,
    evidence: CredentialTransitionEvidence,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
}

impl CompleteCredentialOperation {
    /// Accepts only exact readback evidence and a non-zero lifecycle snapshot.
    pub fn new(
        operation_id: CredentialOperationId,
        evidence: CredentialTransitionEvidence,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
    ) -> Result<Self, CredentialEnrollmentError> {
        BindCredentialReadback::new(operation_id, evidence)?;
        Ok(Self {
            operation_id,
            evidence,
            expected_lifecycle_revision,
            expected_prior_fence,
        })
    }
    /// Returns the operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the exact readback evidence.
    pub const fn evidence(&self) -> CredentialTransitionEvidence {
        self.evidence
    }
    /// Returns the expected revision.
    pub const fn expected_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.expected_lifecycle_revision
    }
    /// Returns the expected fence.
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.expected_prior_fence
    }
}

/// Pre-claim closure request limited to failed, expired, or cancelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosePreparedCredentialOperation {
    operation_id: CredentialOperationId,
    terminal_state: CredentialOperationState,
}

impl ClosePreparedCredentialOperation {
    /// Validates a pre-claim terminal state.
    pub fn new(
        operation_id: CredentialOperationId,
        terminal_state: CredentialOperationState,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !matches!(
            terminal_state,
            CredentialOperationState::Failed
                | CredentialOperationState::Expired
                | CredentialOperationState::Cancelled
        ) {
            return Err(CredentialEnrollmentError::InvalidTransition);
        }
        Ok(Self {
            operation_id,
            terminal_state,
        })
    }
    /// Returns the operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the requested terminal state.
    pub const fn terminal_state(&self) -> CredentialOperationState {
        self.terminal_state
    }
}

/// Retention/cleanup tombstone request for a terminal operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TombstoneCredentialOperation {
    operation_id: CredentialOperationId,
    terminal_state: CredentialOperationState,
}

impl TombstoneCredentialOperation {
    /// Validates a state with a structural edge to tombstoned.
    pub fn new(
        operation_id: CredentialOperationId,
        terminal_state: CredentialOperationState,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !matches!(
            terminal_state,
            CredentialOperationState::Completed
                | CredentialOperationState::Failed
                | CredentialOperationState::Expired
                | CredentialOperationState::Cancelled
        ) {
            return Err(CredentialEnrollmentError::InvalidTransition);
        }
        Ok(Self {
            operation_id,
            terminal_state,
        })
    }
    /// Returns the operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the prior terminal state.
    pub const fn terminal_state(&self) -> CredentialOperationState {
        self.terminal_state
    }
}
