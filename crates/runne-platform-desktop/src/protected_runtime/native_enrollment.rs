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
    ) -> Result<CredentialWriterHandoff, CredentialWriterHandoffError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState.into());
        }
        let writer_launch = confirmed.verified_macos_writer_launch()?;
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .run_credential_writer_handoff(writer_launch, mode)
    }
}

impl ProtectedBundledRuntimeSupervisor {
    /// Linux local-runtime enrollment: assembles the transition claims from
    /// the live V2 launch and runs the V2→V3 transition in place. The owner
    /// intent is launching the local runtime itself; the daemon independently
    /// revalidates the kernel peer, the full signed transcript, and the
    /// installation anchor, then raises the authorization epoch once.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle error when the supervisor is not in a
    /// post-ready state, the live process is gone, or the daemon rejected
    /// the signed transition.
    #[cfg(all(
        target_os = "linux",
        feature = "protected-channel-integration"
    ))]
    pub fn begin_local_linux_enrollment_transition(
        &mut self,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        // Unlike the macOS user-driven flow, the local Linux enrollment runs
        // directly after the V2 launch inside the same connect attempt: the
        // pending V2 profile is intentionally replaced by the enrolled V3 one.
        // The V2 ready frame has been written and the daemon control loop is
        // already reading frames, so `Handshaking` (post-ready, pre-connect)
        // and `Ready` are both valid entry points for the local transition.
        if self.state != BundledRuntimeLifecycleState::Ready
            && self.state != BundledRuntimeLifecycleState::Handshaking
        {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let process = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let claims = process.begin_local_linux_enrollment_claims()?;
        let profile = process
            .begin_credential_enrollment_transition(&claims)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        self.backoff.record_disconnected();
        self.pending_profile = Some(profile);
        self.state = BundledRuntimeLifecycleState::Handshaking;
        Ok(())
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
            let digest = match &self.activation {
                ProtectedProcessActivation::V2 { owned, .. } => *owned.compatibility_owned_launch().executable().executable_sha256(),
                ProtectedProcessActivation::V3 { owned, .. } => *owned.executable().executable_sha256(),
                _ => return Err(ProtectedBundledRuntimeError::InvalidState),
            };
            if !prepared.matches_protected_daemon_digest(digest) {
                return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
            }
            if let ProtectedProcessActivation::V3 { owned, .. } = &self.activation {
                let binding = owned.enrollment_binding();
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?.as_secs();
                if !prepared.matches_qualified_daemon(digest, *binding.release_tuple_digest(),
                    *binding.qualification_binding_digest(), now) {
                    return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
                }
            }
            prepared.confirm_current_daemon(pid)?;
            let after = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
            let confirmation = self.activation.native_confirmation(before.digest(), after.digest())?;
            let confirmed = prepared.confirm(&confirmation)?;
            if let ProtectedProcessActivation::V3 { owned, .. } = &self.activation {
                let binding = owned.enrollment_binding();
                let generation = std::num::NonZeroU64::new(binding.desktop_supervisor_generation())
                    .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
                if confirmed.current_desktop_peer_binding_digest(generation)?
                    != *binding.desktop_peer_binding_digest() {
                    return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
                }
            }
            Ok(confirmed)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = prepared;
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
    }
}
