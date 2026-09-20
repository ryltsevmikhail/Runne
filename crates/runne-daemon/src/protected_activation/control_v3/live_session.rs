use super::*;

/// Revalidates the runtime session while holding its rotation lock.
pub(super) struct LiveEnrollmentSession {
    expected: RuntimeSessionBinding,
}

impl LiveEnrollmentSession {
    /// Captured binding only; callers must still compare it under the lock
    /// before a later mutation, since capture does not prevent rotation.
    pub(super) fn into_binding(self) -> RuntimeSessionBinding {
        self.expected
    }

    pub(super) fn capture(
        sessions: &Mutex<LocalSessionService>,
        owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    ) -> Result<Self, LaunchAuthorityError> {
        let expected = sessions
            .lock()
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?
            .current_binding()
            .clone();
        let stable = expected.stable();
        let owned_stable = owned.stable();
        let ephemeral = expected.ephemeral();
        if ephemeral.daemon_instance_id().as_bytes() != owned.daemon_instance_id()
            || ephemeral.launch_generation() != owned.launch_generation()
            || ephemeral.session_id() != owned.session_id()
            || stable.authority_id() != owned_stable.authority_id()
            || stable.principal_id().as_str() != owned_stable.principal_id()
            || stable.lineage_id().as_bytes() != owned_stable.lineage_id()
            || stable.profile_id() != owned_stable.profile_id()
            || stable.schema_hash() != owned_stable.profile_hash()
            || stable.capability_digest() != owned_stable.capability_digest()
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        Ok(Self { expected })
    }

    pub(super) fn with_current<T>(
        &self,
        sessions: &Mutex<LocalSessionService>,
        action: impl FnOnce() -> Result<T, LaunchAuthorityError>,
    ) -> Result<T, LaunchAuthorityError> {
        let service = sessions
            .lock()
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
        if service.current_binding() != &self.expected {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let result = action();
        drop(service);
        result
    }
}

#[cfg(test)]
// The tests drive the unix enrollment_v3 transport (UnixStream + the
// unix-gated enrollment_v3 fixtures); Windows enrollment is Unsupported.
#[cfg(all(test, unix))]
mod tests;
