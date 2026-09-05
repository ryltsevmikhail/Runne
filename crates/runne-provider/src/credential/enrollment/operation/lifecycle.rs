use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialNativeEffectDisposition, CredentialOperationId,
    CredentialOperationState, CredentialReadbackDisposition, CredentialReadinessObservation,
    CredentialTransitionEvidence,
};

/// Bound writer diagnostic that a native effect may have occurred.
#[derive(Debug, PartialEq, Eq)]
pub struct ObserveNativeEffect {
    operation_id: CredentialOperationId,
    disposition: CredentialNativeEffectDisposition,
}

impl ObserveNativeEffect {
    /// Records a typed, non-secret possible-effect disposition.
    pub const fn new(
        operation_id: CredentialOperationId,
        disposition: CredentialNativeEffectDisposition,
    ) -> Self {
        Self {
            operation_id,
            disposition,
        }
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the safe native-effect disposition.
    pub const fn disposition(&self) -> CredentialNativeEffectDisposition {
        self.disposition
    }
}

/// Exact-absence proof for a failed create/import or superseded cleanup attempt.
#[derive(Debug, PartialEq, Eq)]
pub struct FailCredentialOperation {
    operation_id: CredentialOperationId,
    absence_digest: CredentialBindingDigest,
}

impl FailCredentialOperation {
    /// Binds independently verified exact absence to an operation.
    pub const fn new(
        operation_id: CredentialOperationId,
        absence_digest: CredentialBindingDigest,
    ) -> Self {
        Self {
            operation_id,
            absence_digest,
        }
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the exact absence observation digest.
    pub const fn absence_digest(&self) -> CredentialBindingDigest {
        self.absence_digest
    }
}

/// Independent exact native readback bound to one operation.
#[derive(Debug, PartialEq, Eq)]
pub struct BindCredentialReadback {
    operation_id: CredentialOperationId,
    disposition: CredentialReadbackDisposition,
    observation_digest: CredentialBindingDigest,
}

impl BindCredentialReadback {
    /// Binds one exact version or exact absence observation digest.
    pub const fn new(
        operation_id: CredentialOperationId,
        disposition: CredentialReadbackDisposition,
        observation_digest: CredentialBindingDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        Ok(Self {
            operation_id,
            disposition,
            observation_digest,
        })
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the exact readback disposition.
    pub const fn disposition(&self) -> CredentialReadbackDisposition {
        self.disposition
    }
    /// Returns the exact independent observation digest.
    pub const fn observation_digest(&self) -> CredentialBindingDigest {
        self.observation_digest
    }
    /// Converts this typed readback to the transition-guard evidence vocabulary.
    pub const fn evidence(&self) -> CredentialTransitionEvidence {
        match self.disposition {
            CredentialReadbackDisposition::ExactVersion => {
                CredentialTransitionEvidence::ExactVersionReadback(self.observation_digest)
            }
            CredentialReadbackDisposition::ExactAbsence => {
                CredentialTransitionEvidence::ExactAbsenceReadback(self.observation_digest)
            }
        }
    }
}

/// Lifecycle-CAS completion input after action-specific readback validation.
#[derive(Debug, PartialEq, Eq)]
pub struct CompleteCredentialOperation {
    operation_id: CredentialOperationId,
    readback: BindCredentialReadback,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
    readiness_observation: Option<CredentialReadinessObservation>,
}

impl CompleteCredentialOperation {
    /// Requires an exact readback for the same operation before lifecycle completion.
    pub fn new(
        operation_id: CredentialOperationId,
        readback: BindCredentialReadback,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
    ) -> Result<Self, CredentialEnrollmentError> {
        if readback.operation_id() != operation_id {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            operation_id,
            readback,
            expected_lifecycle_revision,
            expected_prior_fence,
            readiness_observation: None,
        })
    }

    /// Attaches the bounded readiness observation atomically persisted with completion.
    pub fn with_readiness_observation(
        mut self,
        observation: CredentialReadinessObservation,
    ) -> Self {
        self.readiness_observation = Some(observation);
        self
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the exact readback input.
    pub const fn readback(&self) -> &BindCredentialReadback {
        &self.readback
    }
    /// Returns the expected revision.
    pub const fn expected_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.expected_lifecycle_revision
    }
    /// Returns the expected fence.
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.expected_prior_fence
    }
    /// Returns the readiness observation when completion must publish one.
    pub const fn readiness_observation(&self) -> Option<&CredentialReadinessObservation> {
        self.readiness_observation.as_ref()
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
