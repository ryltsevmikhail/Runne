use std::sync::Arc;

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

pub(super) fn unix_now_millis() -> Result<u64, runne_api::LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(runne_api::LaunchAuthorityError::StaleLaunchAuthority)
}

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

pub(crate) struct V3EnrollmentDispatch {
    pub(super) control: Option<
        Arc<
            crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl,
        >,
    >,
    pub(super) rendezvous:
        crate::protected_activation::enrollment_control_transition::DaemonEnrollmentRendezvous,
    pub(super) installed_facts:
        Option<runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts>,
}

impl V3EnrollmentDispatch {
    pub(crate) const fn new(
        control: Option<
            Arc<
                crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl,
            >,
        >,
        rendezvous: crate::protected_activation::enrollment_control_transition::DaemonEnrollmentRendezvous,
        installed_facts: Option<
            runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        >,
    ) -> Self {
        Self {
            control,
            rendezvous,
            installed_facts,
        }
    }
}

pub(super) struct V3EnrollmentRuntime {
    pub(super) broker: Option<crate::protected_activation::broker_handoff::BrokerHandoffDispatch>,
    pub(super) session: Option<
        crate::application::provider_credential_enrollment::DaemonProtectedCredentialEnrollmentSession,
    >,
    pub(super) terminal: bool,
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
    pub(super) fn accepts_shutdown(&self) -> bool {
        self.session.is_none() || self.terminal
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
        &self,
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
            let binding = gateway
                .prepare_rejoin_binding(request, owned, expiry)
                .map_err(map_enrollment_error)?;
            let frame =
                runne_api::CredentialServiceSessionAuthenticator::from_protected_activation(keys)
                    .require_rejoin(binding.clone())
                    .into_control_frame();
            protected.write_control_frame(&frame)?;
            let configuration = self
                .credential_service_configuration
                .clone()
                .ok_or(runne_api::LaunchAuthorityError::OwnershipMismatch)?;
            let session = crate::protected_activation::credential_service_registration::receive_rejoin_registration(
                protected,
                keys,
                &binding,
                configuration,
                unix_now_millis()?,
            )?;
            gateway.install(session).map_err(map_enrollment_error)
        })();
        gateway
            .complete_rejoin(request, result.is_ok())
            .map_err(map_enrollment_error)?;
        result.map(|()| true)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn yield_for_credential_service_rejoin(
        &self,
        protected: &mut crate::protected_activation::ProtectedActivationChannel,
        keys: &runne_api::ProtectedActivationKeys,
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    ) -> Result<bool, runne_api::LaunchAuthorityError> {
        if self.drive_credential_service_rejoin(protected, keys, owned)? {
            return Ok(true);
        }
        if protected.control_frame_ready()? {
            return Ok(false);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        Ok(true)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn drive_claimed_writer(
        &mut self,
        protected: &mut crate::protected_activation::ProtectedActivationChannel,
    ) -> Result<(), runne_api::LaunchAuthorityError> {
        if self.claim_measurements.is_none() || self.channel.is_some() {
            return Ok(());
        }
        let (measurements, continuation) = self
            .claim_measurements
            .take()
            .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?;
        let daemon_start = acquire_after_preflight(
            crate::application::provider_credential_enrollment::broker::MacOsCredentialBrokerChannel::observe_daemon_start,
            || (),
        )?
        .0;
        let session = self
            .session
            .as_mut()
            .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?;
        let installed = session
            .take_installed_facts()
            .map_err(map_enrollment_error)?;
        let writer = self
            .broker
            .as_mut()
            .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?
            .take_verified_writer()
            .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?;
        self.channel = Some(
            crate::application::provider_credential_enrollment::broker::MacOsCredentialBrokerChannel::from_verified(
                writer, installed, daemon_start,
            )
        );
        let broker_channel = self
            .channel
            .as_mut()
            .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?;
        let pending = if let Some(service) = self.credential_service.as_ref() {
            session
                .claim_writer_with_service(measurements, continuation, broker_channel, service)
                .map_err(map_enrollment_error)?
        } else {
            session
                .claim_writer(measurements, continuation, broker_channel)
                .map_err(map_enrollment_error)?
        };
        let released = if let Some(relay) = pending.relay().map(<[u8]>::to_vec) {
            let frame = session.encode_relay(&relay).map_err(map_enrollment_error)?;
            protected.write_control_frame(&frame)?;
            let acknowledgement = protected.read_control_frame()?;
            session
                .accept_relay_ack(&acknowledgement, &relay, pending, broker_channel)
                .map_err(map_enrollment_error)?
        } else {
            return Err(runne_api::LaunchAuthorityError::InvalidContract);
        };
        let now = unix_now_millis()? / 1_000;
        let now =
            i64::try_from(now).map_err(|_| runne_api::LaunchAuthorityError::InvalidContract)?;
        let terminal = session
            .finish_writer(released, broker_channel, now)
            .map_err(map_enrollment_error)?;
        let frame = session
            .encode_terminal_snapshot(terminal)
            .map_err(map_enrollment_error)?;
        protected.write_control_frame(&frame)?;
        self.terminal = true;
        if let Some(channel) = self.channel.take() {
            channel.terminate_exact_writer();
        }
        Ok(())
    }
}

fn acquire_after_preflight<P, A, E>(
    preflight: impl FnOnce() -> Result<P, E>,
    acquire: impl FnOnce() -> A,
) -> Result<(P, A), E> {
    let prepared = preflight()?;
    Ok((prepared, acquire()))
}

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
