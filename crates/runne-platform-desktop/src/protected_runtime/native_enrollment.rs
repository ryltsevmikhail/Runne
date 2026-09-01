use crate::{ConfirmedInstalledNativeEnrollment, PreparedInstalledNativeEnrollment};
#[cfg(target_os = "macos")]
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
#[cfg_attr(not(target_os = "macos"), allow(clippy::needless_pass_by_value))]
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
    /// Transitions the exact owned daemon to V3 and queues its rotated profile.
    ///
    /// No writer launch or handoff is possible through this entry point. The
    /// caller must install the queued profile, complete protected Request and
    /// Begin, and only then invoke [`Self::run_credential_writer_handoff`].
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
    pub fn begin_credential_enrollment_transition(
        &mut self,
        confirmed: &crate::ConfirmedInstalledNativeEnrollment,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let process = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
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
        let profile = process
            .begin_credential_enrollment_transition(&claims)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        self.backoff.record_disconnected();
        self.pending_profile = Some(profile);
        self.state = BundledRuntimeLifecycleState::Handshaking;
        Ok(())
    }

    /// Launches and transfers the verified writer only after protected Begin.
    ///
    /// # Errors
    ///
    /// Returns a closed failure unless the transitioned V3 client has already
    /// been installed and the supervisor is back in authenticated Ready.
    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "protected-channel-integration"
    ))]
    pub fn run_credential_writer_handoff(
        &mut self,
        confirmed: &crate::ConfirmedInstalledNativeEnrollment,
        mode: CredentialWriterHandoffMode,
    ) -> Result<CredentialWriterHandoff, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let writer_launch = confirmed.verified_macos_writer_launch()?;
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .run_credential_writer_handoff(writer_launch, mode)
    }
}

impl ProtectedBundledRuntimeProcess {
    #[cfg_attr(not(target_os = "macos"), allow(clippy::needless_pass_by_value))]
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
