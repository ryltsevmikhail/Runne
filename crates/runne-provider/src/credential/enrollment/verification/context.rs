use std::fmt;

use crate::{CredentialVersionRef, ProviderId};

use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialLifecycleSnapshot, CredentialReadinessRevision,
};

/// Internal current-state context that authorizes one exact verification CAS.
///
/// This deliberately carries only durable bindings, never credential material
/// or a native-store handle. A store may issue it only from one current `READY`
/// observation for the active immutable version.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialVerificationContext {
    lifecycle: CredentialLifecycleSnapshot,
    active_binding_digest: CredentialBindingDigest,
    release_tuple_digest: CredentialBindingDigest,
    observed_at_high_water: i64,
}

impl CredentialVerificationContext {
    /// Validates metadata from one exact current readiness observation.
    ///
    /// # Errors
    ///
    /// Returns an error if the active immutable version and the persisted
    /// binding digest do not agree.
    pub fn new(
        lifecycle: CredentialLifecycleSnapshot,
        active_binding_digest: CredentialBindingDigest,
        release_tuple_digest: CredentialBindingDigest,
        observed_at_high_water: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if observed_at_high_water < 0 {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        let active = lifecycle
            .active_version()
            .ok_or(CredentialEnrollmentError::InvalidInput)?;
        let expected = CredentialBindingDigest::from_measured(*active.ref_digest())?;
        if active_binding_digest != expected {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            lifecycle,
            active_binding_digest,
            release_tuple_digest,
            observed_at_high_water,
        })
    }

    /// Returns the provider with the current active credential.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        self.lifecycle.provider()
    }

    /// Returns the exact active immutable credential version.
    #[must_use]
    pub fn active_version(&self) -> &CredentialVersionRef {
        match self.lifecycle.active_version() {
            Some(active) => active,
            None => unreachable!("verification context requires an active credential"),
        }
    }

    /// Returns the lifecycle revision guarded by the verification CAS.
    #[must_use]
    pub const fn lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.lifecycle.lifecycle_revision()
    }

    /// Returns the credential fence guarded by the verification CAS.
    #[must_use]
    pub const fn fence(&self) -> CredentialFence {
        self.lifecycle.fence()
    }

    /// Returns the current readiness revision.
    #[must_use]
    pub const fn readiness_revision(&self) -> CredentialReadinessRevision {
        self.lifecycle.readiness_revision()
    }

    /// Returns the binding of the current active immutable version.
    #[must_use]
    pub const fn active_binding_digest(&self) -> CredentialBindingDigest {
        self.active_binding_digest
    }

    /// Returns the release tuple bound to the current readiness observation.
    #[must_use]
    pub const fn release_tuple_digest(&self) -> CredentialBindingDigest {
        self.release_tuple_digest
    }

    /// Returns the monotonic observation time bound to the readiness proof.
    #[must_use]
    pub const fn observed_at_high_water(&self) -> i64 {
        self.observed_at_high_water
    }
}

impl fmt::Debug for CredentialVerificationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialVerificationContext(<bound>)")
    }
}
