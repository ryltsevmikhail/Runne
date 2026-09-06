use super::*;
#[cfg(test)]
mod tests;

impl V3EnrollmentRuntime {
    #[cfg(target_os = "macos")]
    pub(in crate::protected_activation::control_v3) fn drive_claimed_writer(
        &mut self,
        protected: &mut crate::protected_activation::ProtectedActivationChannel,
        sessions: &std::sync::Mutex<runne_application::local_session::LocalSessionService>,
        keys: &runne_api::ProtectedActivationKeys,
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    ) -> Result<(), runne_api::LaunchAuthorityError> {
        if self.claim_measurements.is_none() || self.channel.is_some() {
            return Ok(());
        }
        if self.deferred_control.is_some() {
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        // A request queued during the native handoff must complete before claim/arm.
        // Neither failed registration nor crossed control may consume writer authority.
        self.drive_credential_service_rejoin(protected, keys, owned)?;
        if self.deferred_control.is_some() {
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        let live = self
            .live
            .as_ref()
            .ok_or(runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        live.with_current(sessions, || Ok(()))?;
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
        let pending = live.with_current(sessions, || {
            session
                .fence_qualification_before_delivery(
                    owned,
                    broker_channel.installed_measurements(),
                    continuation,
                )
                .map_err(map_enrollment_error)?;
            if let Some(service) = self.credential_service.as_ref() {
                session
                    .claim_writer_with_service(measurements, continuation, broker_channel, service)
                    .map_err(map_enrollment_error)
            } else {
                session
                    .claim_writer(measurements, continuation, broker_channel)
                    .map_err(map_enrollment_error)
            }
        })?;
        let released = if let Some(relay) = pending.relay().map(<[u8]>::to_vec) {
            let frame = session.encode_relay(&relay).map_err(map_enrollment_error)?;
            protected.write_control_frame(&frame)?;
            let acknowledgement = protected.read_control_frame()?;
            live.with_current(sessions, || {
                session
                    .accept_relay_ack(&acknowledgement, &relay, pending, broker_channel)
                    .map_err(map_enrollment_error)
            })?
        } else {
            live.with_current(sessions, || {
                session
                    .release_control_only(pending, broker_channel)
                    .map_err(map_enrollment_error)
            })?
        };
        let now = unix_now_millis()? / 1_000;
        let now =
            i64::try_from(now).map_err(|_| runne_api::LaunchAuthorityError::InvalidContract)?;
        let readback = session
            .prepare_writer_readback(released, broker_channel, now)
            .map_err(map_enrollment_error)?;
        let terminal = completion::with_control(
            || readback().map_err(map_enrollment_error),
            || {
                if self.deferred_control.is_none() {
                    self.drive_credential_service_rejoin(protected, keys, owned)?;
                }
                Ok(())
            },
        );
        let terminal = terminal?;
        self.live
            .as_ref()
            .ok_or(runne_api::LaunchAuthorityError::OwnershipMismatch)?
            .with_current(sessions, || Ok(()))?;
        let frame = self
            .session
            .as_mut()
            .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?
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
