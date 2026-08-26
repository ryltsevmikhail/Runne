use crate::ProviderId;

use super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationId, CredentialVerificationKind,
    CredentialVerificationResult, CredentialVerifierRevision,
};

mod lease;

pub use lease::{CredentialVerificationCapability, CredentialVerificationLease};

/// Store input that begins a bounded credential verification lease.
#[derive(Debug, PartialEq, Eq)]
pub struct BeginCredentialVerification {
    observation_id: CredentialOperationId,
    operation_id: Option<CredentialOperationId>,
    provider_id: ProviderId,
    kind: CredentialVerificationKind,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
    intent_proof_digest: CredentialBindingDigest,
    verifier_revision: CredentialVerifierRevision,
    started_at_high_water: i64,
    expires_at_high_water: i64,
}

impl BeginCredentialVerification {
    /// Validates a digest-only bounded verification request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observation_id: CredentialOperationId,
        operation_id: Option<CredentialOperationId>,
        provider_id: ProviderId,
        kind: CredentialVerificationKind,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
        intent_proof_digest: CredentialBindingDigest,
        verifier_revision: CredentialVerifierRevision,
        started_at_high_water: i64,
        expires_at_high_water: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if started_at_high_water < 0 || expires_at_high_water <= started_at_high_water {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            observation_id,
            operation_id,
            provider_id,
            kind,
            expected_lifecycle_revision,
            expected_prior_fence,
            intent_proof_digest,
            verifier_revision,
            started_at_high_water,
            expires_at_high_water,
        })
    }

    /// Returns the durable verification observation identity.
    pub const fn observation_id(&self) -> CredentialOperationId {
        self.observation_id
    }

    /// Returns the associated operation identity.
    pub const fn operation_id(&self) -> Option<CredentialOperationId> {
        self.operation_id
    }
    /// Returns the provider identity.
    pub const fn provider(&self) -> &ProviderId {
        &self.provider_id
    }
    /// Returns the exact verification kind.
    pub const fn kind(&self) -> CredentialVerificationKind {
        self.kind
    }
    /// Returns the expected lifecycle revision.
    pub const fn expected_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.expected_lifecycle_revision
    }
    /// Returns the expected provider fence.
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.expected_prior_fence
    }
    /// Returns the accepted intent-proof digest.
    pub const fn intent_proof_digest(&self) -> CredentialBindingDigest {
        self.intent_proof_digest
    }
    /// Returns the provider verifier revision.
    pub const fn verifier_revision(&self) -> CredentialVerifierRevision {
        self.verifier_revision
    }
    /// Returns the lease start high-water mark.
    pub const fn started_at_high_water(&self) -> i64 {
        self.started_at_high_water
    }
    /// Returns the absolute expiry high-water mark.
    pub const fn expires_at_high_water(&self) -> i64 {
        self.expires_at_high_water
    }
}
/// Safe verification result observed without response bodies or native errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialVerificationObservation {
    observation_id: CredentialOperationId,
    result: CredentialVerificationResult,
    observed_at_high_water: i64,
}

impl CredentialVerificationObservation {
    /// Validates a bounded safe verification observation.
    pub fn new(
        observation_id: CredentialOperationId,
        result: CredentialVerificationResult,
        observed_at_high_water: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if observed_at_high_water < 0 {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            observation_id,
            result,
            observed_at_high_water,
        })
    }

    /// Returns the durable verification observation identity.
    pub const fn observation_id(&self) -> CredentialOperationId {
        self.observation_id
    }
    /// Returns the safe verification result.
    pub const fn result(&self) -> CredentialVerificationResult {
        self.result
    }
    /// Returns the monotonic observation time.
    pub const fn observed_at_high_water(&self) -> i64 {
        self.observed_at_high_water
    }
}

/// Lifecycle-CAS input that completes one bounded verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompleteCredentialVerification {
    observation: CredentialVerificationObservation,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
}

impl CompleteCredentialVerification {
    /// Binds a safe observation to its expected lifecycle snapshot.
    pub const fn new(
        observation: CredentialVerificationObservation,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
    ) -> Self {
        Self {
            observation,
            expected_lifecycle_revision,
            expected_prior_fence,
        }
    }

    /// Returns the durable verification observation identity.
    pub const fn observation_id(&self) -> CredentialOperationId {
        self.observation.observation_id()
    }
    /// Returns the exact verification observation.
    pub const fn observation(&self) -> &CredentialVerificationObservation {
        &self.observation
    }
    /// Returns the expected lifecycle revision.
    pub const fn expected_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.expected_lifecycle_revision
    }
    /// Returns the expected provider fence.
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.expected_prior_fence
    }
}
