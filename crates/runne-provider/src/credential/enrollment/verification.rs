use crate::ProviderId;

use super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationId, CredentialTransitionEvidence,
};

/// Store input that begins a bounded credential verification lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeginCredentialVerification {
    operation_id: CredentialOperationId,
    provider_id: ProviderId,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
}

impl BeginCredentialVerification {
    /// Constructs a verification request from validated identities and counters.
    pub const fn new(
        operation_id: CredentialOperationId,
        provider_id: ProviderId,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
    ) -> Self {
        Self {
            operation_id,
            provider_id,
            expected_lifecycle_revision,
            expected_prior_fence,
        }
    }

    /// Returns the durable operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }

    /// Returns the provider identity.
    pub const fn provider(&self) -> &ProviderId {
        &self.provider_id
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

/// Store-issued bounded verification lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialVerificationLease {
    begin: BeginCredentialVerification,
    expires_at_high_water: i64,
}

impl CredentialVerificationLease {
    /// Validates a positive high-water expiry.
    pub fn new(
        begin: BeginCredentialVerification,
        expires_at_high_water: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if expires_at_high_water <= 0 {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            begin,
            expires_at_high_water,
        })
    }

    /// Returns the durable operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.begin.operation_id()
    }

    /// Returns the provider identity.
    pub const fn provider(&self) -> &ProviderId {
        self.begin.provider()
    }

    /// Returns the absolute high-water expiry.
    pub const fn expires_at_high_water(&self) -> i64 {
        self.expires_at_high_water
    }
}

/// Process-local authority to materialize a credential for one verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialVerificationCapability {
    lease: CredentialVerificationLease,
    binding_digest: CredentialBindingDigest,
}

impl CredentialVerificationCapability {
    /// Binds a store lease to the exact process-local verifier measurements.
    pub const fn new(
        lease: CredentialVerificationLease,
        binding_digest: CredentialBindingDigest,
    ) -> Self {
        Self {
            lease,
            binding_digest,
        }
    }

    /// Returns the durable operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.lease.operation_id()
    }

    /// Returns the exact capability binding digest.
    pub const fn binding_digest(&self) -> CredentialBindingDigest {
        self.binding_digest
    }

    /// Returns the bounded store lease.
    pub const fn lease(&self) -> &CredentialVerificationLease {
        &self.lease
    }
}

/// Independent exact-version or exact-absence verification observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialVerificationObservation {
    operation_id: CredentialOperationId,
    evidence: CredentialTransitionEvidence,
}

impl CredentialVerificationObservation {
    /// Accepts only an exact native readback observation.
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

    /// Returns the durable operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }

    /// Returns the exact readback evidence.
    pub const fn evidence(&self) -> CredentialTransitionEvidence {
        self.evidence
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
    /// Binds an exact observation to its expected lifecycle snapshot.
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

    /// Returns the durable operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.observation.operation_id()
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
