use crate::ProviderId;

use super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialLifecycleRevision,
    CredentialOperationId,
};

/// Safe writer outcome that requires independent native reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialNativeEffectDisposition {
    /// The writer crossed a boundary where a native mutation may have occurred.
    PossibleEffect,
}

/// Exact class of independently observed native readback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialReadbackDisposition {
    /// The exact target version was observed.
    ExactVersion,
    /// Exact absence was observed after a create/import or delete operation.
    ExactAbsence,
}

/// Safe terminal outcome persisted for replay and tombstone inspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialTerminalDisposition {
    /// A lifecycle cutover or delete completed authoritatively.
    Completed,
    /// Exact independent absence proved the operation did not mutate native state.
    FailedWithVerifiedAbsence,
    /// The operation expired before a ticket claim.
    Expired,
    /// The operation was cancelled before a ticket claim.
    Cancelled,
    /// Retention permanently closed the operation against replay and ABA.
    Tombstoned,
}

/// Closed verification profile kind persisted without network request data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialVerificationKind {
    /// Metadata-only native verification.
    Local,
    /// Explicit bounded provider authentication verification.
    Remote,
}

/// Safe verification result; response bodies and native errors are absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialVerificationResult {
    /// The exact verification profile succeeded.
    Verified,
    /// The verification profile completed without verification.
    Failed,
    /// The profile is unavailable for this provider or platform.
    Unsupported,
    /// A transient dependency prevented verification.
    Unavailable,
    /// Intent or authority was rejected.
    AccessDenied,
    /// Revision, fence, or one-use authority conflicted.
    Conflict,
}

/// Non-zero provider-specific verifier revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialVerifierRevision(u64);

impl CredentialVerifierRevision {
    /// Validates a non-zero verifier profile revision.
    pub fn new(value: u64) -> Result<Self, CredentialEnrollmentError> {
        if value == 0 {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self(value))
    }

    /// Returns the exact verifier profile revision.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Non-zero revision of the provider readiness projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialReadinessRevision(u64);

impl CredentialReadinessRevision {
    /// Validates a non-zero readiness revision.
    pub fn new(value: u64) -> Result<Self, CredentialEnrollmentError> {
        if value == 0 {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self(value))
    }

    /// Returns the exact readiness revision.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Safe readiness disposition from a metadata-only observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialReadinessDisposition {
    /// All current release and native-readback requirements are satisfied.
    Ready,
    /// No active credential is present.
    Missing,
    /// A previous observation is no longer current.
    Stale,
    /// A required dependency is transiently unavailable.
    Unavailable,
    /// The provider or platform does not support this capability.
    Unsupported,
    /// Native or authority access was denied.
    AccessDenied,
    /// Current authority values conflicted.
    Conflict,
    /// A durable invariant failed and the provider is hard-fenced.
    InvariantFailure,
}

/// Metadata-only readiness input associated with one lifecycle revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialReadinessObservation {
    observation_id: CredentialOperationId,
    operation_id: Option<CredentialOperationId>,
    provider_id: ProviderId,
    lifecycle_revision: CredentialLifecycleRevision,
    readiness_revision: CredentialReadinessRevision,
    disposition: CredentialReadinessDisposition,
    active_binding_digest: Option<CredentialBindingDigest>,
    release_tuple_digest: CredentialBindingDigest,
    observed_at_high_water: i64,
}

impl CredentialReadinessObservation {
    /// Validates a bounded safe readiness observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observation_id: CredentialOperationId,
        operation_id: Option<CredentialOperationId>,
        provider_id: ProviderId,
        lifecycle_revision: CredentialLifecycleRevision,
        readiness_revision: CredentialReadinessRevision,
        disposition: CredentialReadinessDisposition,
        active_binding_digest: Option<CredentialBindingDigest>,
        release_tuple_digest: CredentialBindingDigest,
        observed_at_high_water: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if observed_at_high_water < 0
            || (matches!(disposition, CredentialReadinessDisposition::Ready)
                && active_binding_digest.is_none())
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            observation_id,
            operation_id,
            provider_id,
            lifecycle_revision,
            readiness_revision,
            disposition,
            active_binding_digest,
            release_tuple_digest,
            observed_at_high_water,
        })
    }

    /// Returns the durable readiness observation identity.
    pub const fn observation_id(&self) -> CredentialOperationId {
        self.observation_id
    }

    /// Returns the associated operation identity when one exists.
    pub const fn operation_id(&self) -> Option<CredentialOperationId> {
        self.operation_id
    }

    /// Returns the observed provider.
    pub const fn provider(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the bound lifecycle revision.
    pub const fn lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.lifecycle_revision
    }

    /// Returns the authoritative readiness revision.
    pub const fn readiness_revision(&self) -> CredentialReadinessRevision {
        self.readiness_revision
    }

    /// Returns the safe readiness disposition.
    pub const fn disposition(&self) -> CredentialReadinessDisposition {
        self.disposition
    }

    /// Returns the active binding when the observation is ready.
    pub const fn active_binding_digest(&self) -> Option<CredentialBindingDigest> {
        self.active_binding_digest
    }

    /// Returns the release tuple digest used for the observation.
    pub const fn release_tuple_digest(&self) -> CredentialBindingDigest {
        self.release_tuple_digest
    }

    /// Returns the monotonic observation timestamp.
    pub const fn observed_at_high_water(&self) -> i64 {
        self.observed_at_high_water
    }
}
