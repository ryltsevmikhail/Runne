impl ProtectedBundledRuntimeSupervisor {
    /// Begins a daemon-confirmed Linux enrollment transition.
    ///
    /// # Errors
    /// Returns an error when installed evidence is stale or the supervisor or
    /// daemon rejects the transition.
    #[cfg(target_os = "linux")]
    pub fn begin_confirmed_linux_credential_enrollment_transition(
        &mut self,
        confirmed: &crate::ConfirmedInstalledNativeEnrollment,
        resource_directory_hint: &str,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let facts = confirmed.enrollment_transition_facts()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let generation = std::num::NonZeroU64::new(facts.supervisor_generation)
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let claims = EnrollmentTransitionClaims::new(
            facts.release_tuple_digest,
            facts.qualification_binding_digest,
            confirmed.current_desktop_peer_binding_digest(generation)?,
            facts.supervisor_generation,
        );
        let process = self.process.as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let profile = process.begin_confirmed_linux_credential_transition(&claims, resource_directory_hint)?;
        self.backoff.record_disconnected();
        self.pending_profile = Some(profile);
        self.state = BundledRuntimeLifecycleState::Handshaking;
        Ok(())
    }
}

impl ProtectedBundledRuntimeProcess {
    fn begin_confirmed_linux_credential_transition(
        &mut self,
        claims: &EnrollmentTransitionClaims,
        resource_directory_hint: &str,
    ) -> Result<ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeError> {
        if self.graceful_requested || resource_directory_hint.is_empty() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let (compatibility, owned) = match &self.activation {
            ProtectedProcessActivation::V2 { request, owned, .. } => {
                (request.compatibility_request().clone(), owned.clone())
            }
            _ => return Err(ProtectedBundledRuntimeError::InvalidState),
        };
        let mut request_started = false;
        let result = self.run_enrollment_transition_exchange(
            claims,
            &compatibility,
            &owned,
            Some(resource_directory_hint),
            &mut request_started,
        );
        if result.is_err() && request_started {
            self.fence_ambiguous_transition();
        }
        result
    }
}

#[cfg(unix)]
fn unix_wall_millis() -> Result<u64, LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .map_err(|_| LaunchAuthorityError::StaleLaunchAuthority)
}
