use std::sync::Arc;
#[cfg(target_os = "macos")]
mod completion;
#[cfg(all(test, target_os = "macos"))]
pub(in crate::protected_activation) use completion::with_control;
#[cfg(target_os = "macos")]
mod writer_driver;
#[cfg(unix)]
include!("runtime/shutdown.rs");

#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
pub(super) fn map_enrollment_error(
    error: runne_api::ProviderCredentialEnrollmentHostError,
) -> runne_api::LaunchAuthorityError {
    match error {
        runne_api::ProviderCredentialEnrollmentHostError::Unsupported => {
            runne_api::LaunchAuthorityError::UnsupportedPlatformBackend
        }
        runne_api::ProviderCredentialEnrollmentHostError::Unavailable => {
            runne_api::LaunchAuthorityError::ProtectedChannelUnavailable
        }
        _ => runne_api::LaunchAuthorityError::OwnershipMismatch,
    }
}

#[cfg(unix)]
pub(super) fn unix_now_millis() -> Result<u64, runne_api::LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(runne_api::LaunchAuthorityError::StaleLaunchAuthority)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn bind_broker(
    keys: &runne_api::ProtectedActivationKeys,
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    session: &mut crate::application::provider_credential_enrollment::DaemonProtectedCredentialEnrollmentSession,
) -> Result<
    Option<crate::protected_activation::broker_handoff::BrokerHandoffDispatch>,
    runne_api::LaunchAuthorityError,
> {
    if session.begun_is_terminal() {
        return Ok(None);
    }
    let handoff = session
        .take_bound_broker_handoff()
        .map_err(map_enrollment_error)?;
    crate::protected_activation::broker_handoff::BrokerHandoffDispatch::from_bound_enrollment(
        keys, owned, handoff,
    )
    .map(Some)
}

pub(crate) const fn enrollment_transcript_allows_rotation(
    has_session: bool,
    terminal: bool,
) -> bool {
    !has_session || terminal
}

impl V3EnrollmentRuntime {
    /// Off macOS there is no credential enrollment session in the V3 loop.
    pub(super) const fn has_session(&self) -> bool {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            self.session.is_some()
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            false
        }
    }
}

pub(crate) struct V3EnrollmentDispatch {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) round_profile: Option<super::round::RoundProfile>,
    pub(super) control: Option<
        Arc<
            crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl,
        >,
    >,
    pub(super) rendezvous:
        crate::protected_activation::enrollment_control_transition::DaemonEnrollmentRendezvous,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) installed_facts:
        Option<runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts>,
    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    pub(super) qualification_verifier:
        Option<runne_native_qualification::QualificationAdmissionVerifier>,
    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    pub(super) qualification_clock: Option<super::QualificationClock>,
    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    pub(super) qualification_verified: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl V3EnrollmentDispatch {
    pub(crate) const fn new(
        control: Option<
            Arc<
                crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl,
            >,
        >,
        rendezvous: crate::protected_activation::enrollment_control_transition::DaemonEnrollmentRendezvous,
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))] installed_facts: Option<
            runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        >,
    ) -> Self {
        Self {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            round_profile: None,
            control,
            rendezvous,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            installed_facts,
            #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
            qualification_verifier: None,
            #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
            qualification_clock: None,
            #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
            qualification_verified: None,
        }
    }

    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn with_test_qualification(
        mut self,
        verifier: runne_native_qualification::QualificationAdmissionVerifier,
        clock: super::QualificationClock,
        verified: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.qualification_verifier = Some(verifier);
        self.qualification_clock = Some(clock);
        self.qualification_verified = Some(verified);
        self
    }
}

pub(super) struct V3EnrollmentRuntime {
    #[cfg(target_os = "macos")]
    pub(super) deferred_control: Option<zeroize::Zeroizing<Vec<u8>>>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) round: Option<super::round::RoundContext>,
    #[cfg_attr(
        not(all(target_os = "macos", target_arch = "aarch64")),
        allow(dead_code)
    )]
    pub(super) live: Option<super::live_session::LiveEnrollmentSession>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) broker: Option<crate::protected_activation::broker_handoff::BrokerHandoffDispatch>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) session: Option<
        crate::application::provider_credential_enrollment::DaemonProtectedCredentialEnrollmentSession,
    >,
    pub(super) terminal: bool,
    #[cfg(target_os = "macos")]
    pub(super) claim_measurements: Option<(
        runne_provider::CredentialMeasurementSnapshot,
        runne_provider::CredentialBindingDigest,
    )>,
    #[cfg(target_os = "macos")]
    pub(super) channel: Option<
        crate::application::provider_credential_enrollment::broker::MacOsCredentialBrokerChannel,
    >,
    #[cfg(target_os = "macos")]
    pub(super) credential_service:
        Option<Arc<crate::protected_activation::CredentialServiceRuntimeGateway>>,
    #[cfg(target_os = "macos")]
    pub(super) credential_service_configuration:
        Option<runne_macos_xpc::CredentialServiceEndpointConfiguration>,
}

impl V3EnrollmentRuntime {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) fn require_shutdown(&self) -> Result<(), runne_api::LaunchAuthorityError> {
        require_shutdown_terminal(self.session.as_ref(), self.terminal)
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(super) fn require_shutdown(&self) -> Result<(), runne_api::LaunchAuthorityError> {
        let _ = self.terminal;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(super) fn terminate_retained_writer(&mut self) {
        if let Some(channel) = self.channel.take() {
            channel.terminate_exact_writer();
        }
        if let Some(broker) = self.broker.as_mut() {
            broker.terminate_retained_writer();
        }
    }

    #[cfg(target_os = "macos")]
    pub(super) fn drive_credential_service_rejoin(
        &mut self,
        protected: &mut crate::protected_activation::ProtectedActivationChannel,
        keys: &runne_api::ProtectedActivationKeys,
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    ) -> Result<bool, runne_api::LaunchAuthorityError> {
        let Some(gateway) = self.credential_service.as_ref() else {
            return Ok(false);
        };
        let Some(request) = gateway
            .take_rejoin_request()
            .map_err(map_enrollment_error)?
        else {
            return Ok(false);
        };
        let result = (|| {
            let now = unix_now_millis()?;
            let expiry = now
                .checked_add(5_000)
                .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?;
            let prepared = gateway
                .prepare_rejoin_binding(request, owned, expiry)
                .map_err(map_enrollment_error)?;
            let frame =
                runne_api::CredentialServiceSessionAuthenticator::from_protected_activation(keys)
                    .require_rejoin(prepared.binding.clone())
                    .into_control_frame();
            protected.write_control_frame(&frame)?;
            let configuration = self
                .credential_service_configuration
                .clone()
                .ok_or(runne_api::LaunchAuthorityError::OwnershipMismatch)?;
            let rejoined = crate::protected_activation::credential_service_registration::receive_rejoin_registration(
                protected,
                keys,
                &prepared,
                configuration,
                unix_now_millis()?,
            )?;
            gateway
                .install(rejoined.session)
                .map_err(map_enrollment_error)?;
            Ok(rejoined.deferred)
        })();
        gateway
            .complete_rejoin(request, result.is_ok())
            .map_err(map_enrollment_error)?;
        self.deferred_control = result?;
        Ok(true)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn yield_for_credential_service_rejoin(
        &mut self,
        protected: &mut crate::protected_activation::ProtectedActivationChannel,
        keys: &runne_api::ProtectedActivationKeys,
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    ) -> Result<bool, runne_api::LaunchAuthorityError> {
        if self.deferred_control.is_some() {
            return Ok(false);
        }
        if self.drive_credential_service_rejoin(protected, keys, owned)? {
            return Ok(true);
        }
        if protected.control_frame_ready()? {
            return Ok(false);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        Ok(true)
    }
}

#[cfg_attr(
    not(any(
        all(test, unix),
        all(target_os = "macos", target_arch = "aarch64")
    )),
    allow(dead_code)
)]
pub(crate) fn require_shutdown_terminal(
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    session: Option<&()>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    session: Option<&crate::application::provider_credential_enrollment::DaemonProtectedCredentialEnrollmentSession>,
    terminal: bool,
) -> Result<(), runne_api::LaunchAuthorityError> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        if session.is_some() && !terminal {
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        if let Some(session) = session {
            session
                .require_durable_terminal()
                .map_err(map_enrollment_error)?;
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (session, terminal);
    }
    Ok(())
}

#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
fn acquire_after_preflight<P, A, E>(
    preflight: impl FnOnce() -> Result<P, E>,
    acquire: impl FnOnce() -> A,
) -> Result<(P, A), E> {
    let prepared = preflight()?;
    Ok((prepared, acquire()))
}

#[cfg(test)]
#[path = "runtime_cfg_scope_tests.rs"]
mod cfg_scope_tests;
#[cfg(test)]
mod tests {
    use std::cell::Cell;

    #[test]
    fn failed_channel_preflight_does_not_take_writer_authority() {
        let acquired = Cell::new(false);
        let result = super::acquire_after_preflight(
            || Err::<(), _>("daemon-start-unavailable"),
            || acquired.set(true),
        );
        assert_eq!(result, Err("daemon-start-unavailable"));
        assert!(!acquired.get());
    }
}
