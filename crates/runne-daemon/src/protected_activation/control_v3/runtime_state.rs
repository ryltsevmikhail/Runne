// `V3EnrollmentRuntime` carries the per-connection V3 state: the retained
// live session, the terminal fence, and the macOS-only credential-service
// rejoin machinery. Splitting the macOS rejoin drivers out of `runtime.rs`
// keeps every file in this module under the 300-line source limit.

use super::super::live_session;

pub(crate) struct V3EnrollmentRuntime {
    #[cfg(target_os = "macos")]
    pub(super) deferred_control: Option<zeroize::Zeroizing<Vec<u8>>>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) round: Option<super::round::RoundContext>,
    #[cfg_attr(
        not(all(target_os = "macos", target_arch = "aarch64")),
        allow(dead_code)
    )]
    pub(crate) live: Option<live_session::LiveEnrollmentSession>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) broker: Option<crate::protected_activation::broker_handoff::BrokerHandoffDispatch>,
    #[cfg(any(
        target_os = "linux",
        all(target_os = "macos", target_arch = "aarch64")
    ))]
    pub(crate) session: Option<
        crate::application::provider_credential_enrollment::DaemonProtectedCredentialEnrollmentSession,
    >,
    pub(crate) terminal: bool,
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
    /// Reports whether V3 retains an enrollment session for this Unix target.
    pub(crate) const fn has_session(&self) -> bool {
        #[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
        {
            self.session.is_some()
        }
        #[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
        {
            false
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn require_shutdown(&self) -> Result<(), runne_api::LaunchAuthorityError> {
        super::require_shutdown_terminal(self.session.as_ref(), self.terminal)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn require_shutdown(&self) -> Result<(), runne_api::LaunchAuthorityError> {
        if self.session.is_some() && !self.terminal {
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        if let Some(session) = self.session.as_ref() {
            session
                .require_durable_terminal()
                .map_err(super::map_enrollment_error)?;
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
    pub(crate) fn require_shutdown(&self) -> Result<(), runne_api::LaunchAuthorityError> {
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
            .map_err(super::map_enrollment_error)?
        else {
            return Ok(false);
        };
        let result = (|| {
            let now = super::unix_now_millis()?;
            let expiry = now
                .checked_add(5_000)
                .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?;
            let prepared = gateway
                .prepare_rejoin_binding(request, owned, expiry)
                .map_err(super::map_enrollment_error)?;
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
                super::unix_now_millis()?,
            )?;
            gateway
                .install(rejoined.session)
                .map_err(super::map_enrollment_error)?;
            Ok(rejoined.deferred)
        })();
        gateway
            .complete_rejoin(request, result.is_ok())
            .map_err(super::map_enrollment_error)?;
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
