use crate::ProviderId;

use super::{
    CredentialEnrollmentError, CredentialLifecycleRevision, CredentialReadinessDisposition,
    CredentialReadinessRevision, CredentialVerificationKind, CredentialVerificationResult,
    CredentialVerifierRevision,
};

/// Metadata-only current verification state for one provider lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialVerificationSnapshot {
    kind: Option<CredentialVerificationKind>,
    result: Option<CredentialVerificationResult>,
    verifier_revision: Option<CredentialVerifierRevision>,
    observed_at_high_water: Option<i64>,
}

impl CredentialVerificationSnapshot {
    /// Represents a provider with no current verification observation.
    pub const fn not_verified() -> Self {
        Self {
            kind: None,
            result: None,
            verifier_revision: None,
            observed_at_high_water: None,
        }
    }

    /// Represents an in-progress, bounded verification lease.
    pub fn pending(
        kind: CredentialVerificationKind,
        verifier_revision: CredentialVerifierRevision,
    ) -> Result<Self, CredentialEnrollmentError> {
        if verifier_revision.get() == 0 {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            kind: Some(kind),
            result: None,
            verifier_revision: Some(verifier_revision),
            observed_at_high_water: None,
        })
    }

    /// Represents a completed metadata-only verification observation.
    pub fn completed(
        kind: CredentialVerificationKind,
        result: CredentialVerificationResult,
        verifier_revision: CredentialVerifierRevision,
        observed_at_high_water: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if observed_at_high_water < 0 || verifier_revision.get() == 0 {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            kind: Some(kind),
            result: Some(result),
            verifier_revision: Some(verifier_revision),
            observed_at_high_water: Some(observed_at_high_water),
        })
    }

    /// Returns the verification kind when a current observation exists.
    pub const fn kind(&self) -> Option<CredentialVerificationKind> {
        self.kind
    }

    /// Returns the terminal result; `None` means no observation or pending work.
    pub const fn result(&self) -> Option<CredentialVerificationResult> {
        self.result
    }

    /// Returns the provider verifier revision when a current observation exists.
    pub const fn verifier_revision(&self) -> Option<CredentialVerifierRevision> {
        self.verifier_revision
    }

    /// Returns the completion high-water mark only for terminal verification.
    pub const fn observed_at_high_water(&self) -> Option<i64> {
        self.observed_at_high_water
    }

    /// Returns whether the latest verification lease is still pending.
    pub const fn is_pending(&self) -> bool {
        self.kind.is_some() && self.result.is_none()
    }
}

/// Current metadata-only provider credential projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialSafeSnapshot {
    provider: ProviderId,
    configured: bool,
    lifecycle_revision: CredentialLifecycleRevision,
    readiness_revision: CredentialReadinessRevision,
    readiness: CredentialReadinessDisposition,
    observed_at_high_water: i64,
    verification: CredentialVerificationSnapshot,
}

impl CredentialSafeSnapshot {
    /// Constructs a validated projection with no secret, ticket, path, or digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: ProviderId,
        configured: bool,
        lifecycle_revision: CredentialLifecycleRevision,
        readiness_revision: CredentialReadinessRevision,
        readiness: CredentialReadinessDisposition,
        observed_at_high_water: i64,
        verification: CredentialVerificationSnapshot,
    ) -> Result<Self, CredentialEnrollmentError> {
        if observed_at_high_water < 0 {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            provider,
            configured,
            lifecycle_revision,
            readiness_revision,
            readiness,
            observed_at_high_water,
            verification,
        })
    }

    /// Returns the provider identity.
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns whether an active credential version is currently configured.
    pub const fn configured(&self) -> bool {
        self.configured
    }

    /// Returns the current lifecycle revision.
    pub const fn lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.lifecycle_revision
    }

    /// Returns the current readiness revision.
    pub const fn readiness_revision(&self) -> CredentialReadinessRevision {
        self.readiness_revision
    }

    /// Returns the current safe readiness disposition.
    pub const fn readiness(&self) -> CredentialReadinessDisposition {
        self.readiness
    }

    /// Returns the current safe observation high-water mark.
    pub const fn observed_at_high_water(&self) -> i64 {
        self.observed_at_high_water
    }

    /// Returns current metadata-only verification state.
    pub const fn verification(&self) -> &CredentialVerificationSnapshot {
        &self.verification
    }
}
