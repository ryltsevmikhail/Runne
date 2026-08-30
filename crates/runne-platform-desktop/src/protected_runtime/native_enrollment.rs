use crate::{ConfirmedInstalledNativeEnrollment, PreparedInstalledNativeEnrollment};
use crate::updater_metadata::NativeEnrollmentConfirmationV1;

impl ProtectedBundledRuntimeSupervisor {
    /// Revalidates one retained installed release tuple against the exact current daemon.
    ///
    /// The prepared value is consumed: callers cannot replay confirmation after a
    /// prompt delay, lifecycle transition, or daemon replacement.
    ///
    /// # Errors
    ///
    /// Returns a closed failure unless the exact owned provider-bound daemon is
    /// ready and the retained installed release tuple still matches it.
    pub fn confirm_installed_native_enrollment(
        &mut self,
        prepared: PreparedInstalledNativeEnrollment,
    ) -> Result<ConfirmedInstalledNativeEnrollment, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .confirm_installed_native_enrollment(prepared)
    }
}

impl ProtectedBundledRuntimeSupervisor {
    /// Transitions the exact owned daemon to V3 and hands off one verified
    /// writer, in that order, for one confirmed installed enrollment.
    ///
    /// The writer launch is minted before the transition mutates daemon state;
    /// a handoff failure poisons the whole transport and leaves the daemon
    /// holding the sole kill path.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for any stale supervisor state, retained
    /// admission, live peer, transition, or handoff failure.
    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "protected-channel-integration"
    ))]
    pub fn begin_credential_enrollment_handoff(
        &mut self,
        confirmed: &crate::ConfirmedInstalledNativeEnrollment,
    ) -> Result<CredentialWriterHandoff, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let process = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let writer_launch = confirmed.verified_macos_writer_launch()?;
        let facts = confirmed
            .enrollment_transition_facts()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let supervisor_generation =
            std::num::NonZeroU64::new(facts.supervisor_generation)
                .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let claims = EnrollmentTransitionClaims::new(
            facts.release_tuple_digest,
            facts.qualification_binding_digest,
            confirmed.current_desktop_peer_binding_digest(supervisor_generation)?,
            facts.supervisor_generation,
        );
        let _transitioned = process
            .begin_credential_enrollment_transition(&claims)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        process.run_credential_writer_handoff(writer_launch)
    }
}

impl ProtectedBundledRuntimeProcess {
    fn confirm_installed_native_enrollment(
        &mut self,
        prepared: PreparedInstalledNativeEnrollment,
    ) -> Result<ConfirmedInstalledNativeEnrollment, ProtectedBundledRuntimeError> {
        if self.graceful_requested
            || self.activation.provider_activation().is_none()
            || self.status()? != BundledRuntimeProcessStatus::Running
        {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        #[cfg(target_os = "macos")]
        {
            let pid = std::num::NonZeroU32::new(self.child.id())
                .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
            let before = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
            let owned = self
                .activation
                .compatibility_owned()
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            if !prepared.matches_protected_daemon_digest(*owned.executable().executable_sha256()) {
                return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
            }
            prepared.confirm_current_daemon(pid)?;
            let after = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
            let confirmation = NativeEnrollmentConfirmationV1 {
                process_start_before: before.digest(),
                process_start_after: after.digest(),
                launch_authority: *owned.launch_authority_id(),
                desktop_host: *owned.desktop_host_instance_id(),
                session: *owned.session_id(),
                daemon: *owned.daemon_instance_id(),
                generation: owned.launch_generation(),
            };
            prepared.confirm(&confirmation)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = prepared;
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
    }
}
