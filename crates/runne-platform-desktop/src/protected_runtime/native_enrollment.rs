#[cfg(target_os = "macos")]
use crate::updater_metadata::NativeEnrollmentConfirmationV1;
use crate::{ConfirmedInstalledNativeEnrollment, PreparedInstalledNativeEnrollment};

impl ProtectedBundledRuntimeSupervisor {
    /// Reports the protocol version of the queued authenticated runtime profile.
    ///
    /// # Errors
    /// Returns an error unless one pending profile is owned during handshaking.
    #[cfg(target_os = "linux")]
    pub fn pending_profile_is_v3(&self) -> Result<bool, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Handshaking {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.pending_profile
            .as_ref()
            .map(|profile| profile.enrollment_owned_launch().is_some())
            .ok_or(ProtectedBundledRuntimeError::InvalidState)
    }

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

#[cfg(target_os = "linux")]
fn linux_process_start_ticks(pid: u32) -> Result<u64, ProtectedBundledRuntimeError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)
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
        let supervisor_generation = std::num::NonZeroU64::new(facts.supervisor_generation)
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
                ProtectedProcessActivation::V2 { owned, .. } => *owned
                    .compatibility_owned_launch()
                    .executable()
                    .executable_sha256(),
                ProtectedProcessActivation::V3 { owned, .. } => {
                    *owned.executable().executable_sha256()
                }
                _ => return Err(ProtectedBundledRuntimeError::InvalidState),
            };
            if !prepared.matches_protected_daemon_digest(digest) {
                return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
            }
            if let ProtectedProcessActivation::V3 { owned, .. } = &self.activation {
                let binding = owned.enrollment_binding();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?
                    .as_secs();
                if !prepared.matches_qualified_daemon(
                    digest,
                    *binding.release_tuple_digest(),
                    *binding.qualification_binding_digest(),
                    now,
                ) {
                    return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
                }
            }
            prepared.confirm_current_daemon(pid)?;
            let after = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
            let confirmation = self
                .activation
                .native_confirmation(before.digest(), after.digest())?;
            let confirmed = prepared.confirm(&confirmation)?;
            if let ProtectedProcessActivation::V3 { owned, .. } = &self.activation {
                let binding = owned.enrollment_binding();
                let generation = std::num::NonZeroU64::new(binding.desktop_supervisor_generation())
                    .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
                if confirmed.current_desktop_peer_binding_digest(generation)?
                    != *binding.desktop_peer_binding_digest()
                {
                    return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
                }
            }
            Ok(confirmed)
        }
        #[cfg(target_os = "linux")]
        {
            use sha2::{Digest as _, Sha256};
            let pid = self.child.id();
            let credentials = rustix::net::sockopt::socket_peercred(&self.channel)
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
            if u32::try_from(credentials.pid.as_raw_pid()).ok() != Some(pid)
                || credentials.uid != rustix::process::geteuid()
            {
                return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
            }
            let before = linux_process_start_ticks(pid)?;
            prepared.confirm_linux_daemon_image(pid, before)?;
            let (authority, desktop, session, daemon, generation) = match &self.activation {
                ProtectedProcessActivation::V2 { owned, .. } => (
                    *owned.launch_authority_id(),
                    *owned.desktop_host_instance_id(),
                    *owned.session_id(),
                    *owned.daemon_instance_id(),
                    owned.launch_generation(),
                ),
                ProtectedProcessActivation::V3 { owned, .. } => (
                    *owned.launch_authority_id(),
                    *owned.desktop_host_instance_id(),
                    *owned.session_id(),
                    *owned.daemon_instance_id(),
                    owned.launch_generation(),
                ),
                _ => return Err(ProtectedBundledRuntimeError::InvalidState),
            };
            let after = linux_process_start_ticks(pid)?;
            if before != after {
                return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
            }
            let mut hash = Sha256::new();
            hash.update(b"runne/linux-live-daemon-process/v1\0");
            hash.update(pid.to_be_bytes());
            hash.update(after.to_be_bytes());
            prepared.confirm_linux(
                authority,
                desktop,
                session,
                daemon,
                generation,
                hash.finalize().into(),
            )
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = prepared;
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
    }
}
