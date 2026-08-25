use std::sync::Arc;

use crate::ProviderId;

use super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationId, CredentialVerificationKind,
    CredentialVerificationResult, CredentialVerifierRevision, authority::EnrollmentAuthoritySeal,
};

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
/// Store-issued bounded verification lease.
///
/// ```compile_fail
/// use runne_provider::{BeginCredentialVerification, CredentialVerificationLease};
/// let _: fn(BeginCredentialVerification) -> CredentialVerificationLease =
///     CredentialVerificationLease::new;
/// ```
#[derive(Debug)]
pub struct CredentialVerificationLease {
    begin: BeginCredentialVerification,
    seal: Arc<EnrollmentAuthoritySeal>,
}
impl PartialEq for CredentialVerificationLease {
    fn eq(&self, other: &Self) -> bool {
        self.begin == other.begin && Arc::ptr_eq(&self.seal, &other.seal)
    }
}

impl Eq for CredentialVerificationLease {}

impl CredentialVerificationLease {
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        begin: BeginCredentialVerification,
    ) -> Self {
        Self { begin, seal }
    }

    /// Returns the durable operation identity.
    pub const fn observation_id(&self) -> CredentialOperationId {
        self.begin.observation_id()
    }

    /// Returns the associated operation identity when one exists.
    pub const fn operation_id(&self) -> Option<CredentialOperationId> {
        self.begin.operation_id()
    }
    /// Returns the provider identity.
    pub const fn provider(&self) -> &ProviderId {
        self.begin.provider()
    }
    /// Returns the exact verification kind.
    pub const fn kind(&self) -> CredentialVerificationKind {
        self.begin.kind()
    }
    /// Returns the accepted intent-proof digest.
    pub const fn intent_proof_digest(&self) -> CredentialBindingDigest {
        self.begin.intent_proof_digest()
    }
    /// Returns the provider verifier revision.
    pub const fn verifier_revision(&self) -> CredentialVerifierRevision {
        self.begin.verifier_revision()
    }
    /// Returns the absolute high-water expiry.
    pub const fn expires_at_high_water(&self) -> i64 {
        self.begin.expires_at_high_water()
    }

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }
}

/// Process-local authority to materialize a credential for one verification.
///
/// ```compile_fail
/// use runne_provider::{CredentialBindingDigest, CredentialVerificationCapability, CredentialVerificationLease};
/// let _: fn(CredentialVerificationLease, CredentialBindingDigest) -> CredentialVerificationCapability =
///     CredentialVerificationCapability::new;
/// ```
#[derive(Debug)]
pub struct CredentialVerificationCapability {
    lease: CredentialVerificationLease,
    binding_digest: CredentialBindingDigest,
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl PartialEq for CredentialVerificationCapability {
    fn eq(&self, other: &Self) -> bool {
        self.lease == other.lease
            && self.binding_digest == other.binding_digest
            && Arc::ptr_eq(&self.seal, &other.seal)
    }
}

impl Eq for CredentialVerificationCapability {}

impl CredentialVerificationCapability {
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        lease: CredentialVerificationLease,
        binding_digest: CredentialBindingDigest,
    ) -> Self {
        Self {
            lease,
            binding_digest,
            seal,
        }
    }

    /// Returns the durable verification observation identity.
    pub const fn observation_id(&self) -> CredentialOperationId {
        self.lease.observation_id()
    }
    /// Returns the associated operation identity when one exists.
    pub const fn operation_id(&self) -> Option<CredentialOperationId> {
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

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal) && self.lease.belongs_to(seal)
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
