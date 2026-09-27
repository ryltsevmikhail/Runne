use super::*;

impl LinuxEnrollmentWriter {
    pub(in crate::protected_activation::control_v3) fn drive_claimed_writer(
        &mut self,
        protected: &mut crate::protected_activation::ProtectedActivationChannel,
        sessions: &std::sync::Mutex<runne_application::local_session::LocalSessionService>,
        keys: &runne_api::ProtectedActivationKeys,
        session: &mut DaemonProtectedCredentialEnrollmentSession,
        live: &super::super::super::live_session::LiveEnrollmentSession,
    ) -> Result<(), runne_api::LaunchAuthorityError> {
        if self.channel.is_none() || self.claim_measurements.is_none() {
            pair_diag("writer_claim_preflight", false);
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        if !self
            .capability
            .revalidate_for_authenticated_desktop_peer(protected.unix_stream())
        {
            pair_diag("writer_claim_preflight", false);
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        let current = self.capability.measurement_facts(protected.unix_stream());
        pair_diag("writer_peer_remeasurement", current.is_some());
        let current = current.ok_or(runne_api::LaunchAuthorityError::OwnershipMismatch)?;
        if !same_release(&self.installed, &current) {
            pair_diag("writer_peer_release_match", false);
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        pair_diag("writer_peer_release_match", true);
        if self.channel_binding == [0; 32] || self.publication_key == [0; 32] {
            pair_diag("writer_claim_preflight", false);
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        let live_result = live.with_current(sessions, || Ok(()));
        pair_diag("writer_live_session", live_result.is_ok());
        live_result?;
        let (measurements, continuation) = self
            .claim_measurements
            .take()
            .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?;
        let broker_channel = self
            .channel
            .as_mut()
            .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?;
        pair_diag("writer_claim_preflight", true);
        let claim = live.with_current(sessions, || {
            session
                .claim_writer(measurements, continuation, broker_channel)
                .map_err(map_enrollment_error)
        });
        pair_diag("writer_ticket_claim_pipeline", claim.is_ok());
        let pending = claim?;
        let released = if let Some(relay_bytes) = pending.relay().map(<[u8]>::to_vec) {
            let frame = stage_result(
                "writer_relay_encode",
                session
                    .encode_relay(&relay_bytes)
                    .map_err(map_enrollment_error),
            )?;
            stage_result(
                "writer_relay_frame_write",
                protected.write_control_frame(&frame),
            )?;
            let peer_valid = self
                .capability
                .revalidate_for_authenticated_desktop_peer(protected.unix_stream())
                && self
                    .capability
                    .measurement_facts(protected.unix_stream())
                    .is_some_and(|facts| same_release(&self.installed, &facts));
            pair_diag("writer_relay_peer_revalidation", peer_valid);
            if !peer_valid {
                return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
            }
            let secret_relay = self
                .relay
                .take()
                .ok_or(runne_api::LaunchAuthorityError::OwnershipMismatch)?;
            let offer_auth =
                runne_api::LinuxPairSecretRelayOfferAuthenticator::from_protected_activation(keys);
            stage_result(
                "writer_secret_relay_offer",
                secret_relay
                    .offer_linux_over_protected_stream(protected.unix_stream(), &offer_auth, &frame)
                    .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch),
            )?;
            let acknowledgement =
                stage_result("writer_desktop_ack_read", protected.read_control_frame())?;
            stage_result(
                "writer_desktop_ack_accept",
                live.with_current(sessions, || {
                    session
                        .accept_relay_ack(&acknowledgement, &relay_bytes, pending, broker_channel)
                        .map_err(map_enrollment_error)
                }),
            )?
        } else {
            if self.relay.is_some() {
                return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
            }
            live.with_current(sessions, || {
                session
                    .release_control_only(pending, broker_channel)
                    .map_err(map_enrollment_error)
            })?
        };
        let now = unix_now_millis()? / 1_000;
        let now =
            i64::try_from(now).map_err(|_| runne_api::LaunchAuthorityError::InvalidContract)?;
        let readback = stage_result(
            "writer_terminal_readback_prepare",
            session
                .prepare_writer_readback(released, broker_channel, now)
                .map_err(map_enrollment_error),
        )?;
        let terminal = stage_result(
            "writer_terminal_readback",
            readback().map_err(map_enrollment_error),
        )?;
        let live_result = live.with_current(sessions, || Ok(()));
        pair_diag("writer_terminal_live_session", live_result.is_ok());
        live_result?;
        let terminal_peer_valid = self
            .capability
            .revalidate_for_authenticated_desktop_peer(protected.unix_stream());
        pair_diag("writer_terminal_peer_revalidation", terminal_peer_valid);
        if !terminal_peer_valid {
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        let frame = stage_result(
            "writer_terminal_snapshot_encode",
            session
                .encode_terminal_snapshot(terminal)
                .map_err(map_enrollment_error),
        )?;
        stage_result(
            "writer_channel_terminate",
            self.channel
                .take()
                .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?
                .terminate_exact_writer()
                .map_err(map_enrollment_error),
        )?;
        stage_result(
            "writer_terminal_frame_write",
            protected.write_control_frame(&frame),
        )?;
        Ok(())
    }
}
