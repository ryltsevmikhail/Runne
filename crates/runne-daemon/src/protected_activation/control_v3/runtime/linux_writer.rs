use super::*;
use crate::application::provider_credential_enrollment::DaemonProtectedCredentialEnrollmentSession;
use crate::application::provider_credential_enrollment::broker::{
    CredentialBrokerChannel, LinuxCredentialBrokerChannel, launch_verified_linux_control_writer,
    launch_verified_linux_pair_writer,
};
use crate::protected_activation::linux_pair_diagnostics::record as pair_diag;
use rand::RngCore as _;
use runne_platform_desktop::{
    VerifiedInstalledLinuxEnrollmentMeasurementFacts, VerifiedInstalledLinuxWriterCapability,
    provider_credential_broker::LinuxAuthenticatedPairSecretRelay,
};
use std::os::unix::net::UnixStream;
use zeroize::{Zeroize as _, Zeroizing};

pub(crate) struct LinuxEnrollmentWriter {
    pub(super) capability: std::sync::Arc<VerifiedInstalledLinuxWriterCapability>,
    pub(super) installed: VerifiedInstalledLinuxEnrollmentMeasurementFacts,
    pub(super) channel_binding: [u8; 32],
    pub(super) publication_key: [u8; 32],
    pub(super) channel: Option<LinuxCredentialBrokerChannel>,
    pub(super) relay: Option<LinuxAuthenticatedPairSecretRelay>,
    pub(super) claim_measurements: Option<(
        runne_provider::CredentialMeasurementSnapshot,
        runne_provider::CredentialBindingDigest,
    )>,
}

impl LinuxEnrollmentWriter {
    pub(in crate::protected_activation::control_v3) fn in_flight(&self) -> bool {
        self.channel.is_some() || self.claim_measurements.is_some()
    }

    pub(in crate::protected_activation::control_v3) fn drive_claimed_writer(
        &mut self,
        protected: &mut crate::protected_activation::ProtectedActivationChannel,
        sessions: &std::sync::Mutex<runne_application::local_session::LocalSessionService>,
        keys: &runne_api::ProtectedActivationKeys,
        session: &mut DaemonProtectedCredentialEnrollmentSession,
        live: &super::super::live_session::LiveEnrollmentSession,
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
            let frame = session
                .encode_relay(&relay_bytes)
                .map_err(map_enrollment_error)?;
            protected.write_control_frame(&frame)?;
            if !self
                .capability
                .revalidate_for_authenticated_desktop_peer(protected.unix_stream())
                || self
                    .capability
                    .measurement_facts(protected.unix_stream())
                    .is_none_or(|facts| !same_release(&self.installed, &facts))
            {
                return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
            }
            let secret_relay = self
                .relay
                .take()
                .ok_or(runne_api::LaunchAuthorityError::OwnershipMismatch)?;
            let offer_auth =
                runne_api::LinuxPairSecretRelayOfferAuthenticator::from_protected_activation(keys);
            secret_relay
                .offer_linux_over_protected_stream(protected.unix_stream(), &offer_auth, &frame)
                .map_err(|_| runne_api::LaunchAuthorityError::OwnershipMismatch)?;
            let acknowledgement = protected.read_control_frame()?;
            live.with_current(sessions, || {
                session
                    .accept_relay_ack(&acknowledgement, &relay_bytes, pending, broker_channel)
                    .map_err(map_enrollment_error)
            })?
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
        let readback = session
            .prepare_writer_readback(released, broker_channel, now)
            .map_err(map_enrollment_error)?;
        let terminal = readback().map_err(map_enrollment_error)?;
        live.with_current(sessions, || Ok(()))?;
        if !self
            .capability
            .revalidate_for_authenticated_desktop_peer(protected.unix_stream())
        {
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        let frame = session
            .encode_terminal_snapshot(terminal)
            .map_err(map_enrollment_error)?;
        self.channel
            .take()
            .ok_or(runne_api::LaunchAuthorityError::InvalidContract)?
            .terminate_exact_writer()
            .map_err(map_enrollment_error)?;
        protected.write_control_frame(&frame)?;
        Ok(())
    }

    pub(super) fn terminate(
        &mut self,
    ) -> Result<(), runne_api::ProviderCredentialEnrollmentHostError> {
        self.relay.take();
        if let Some(channel) = self.channel.take() {
            channel.terminate_exact_writer()?;
        }
        Ok(())
    }
}

pub fn launch_after_begin(
    enrollment: &mut DaemonProtectedCredentialEnrollmentSession,
    capability: std::sync::Arc<VerifiedInstalledLinuxWriterCapability>,
    stream: &UnixStream,
    keys: &runne_api::ProtectedActivationKeys,
) -> Result<LinuxEnrollmentWriter, runne_api::LaunchAuthorityError> {
    if !capability.revalidate_for_authenticated_desktop_peer(stream) {
        pair_diag("writer_capability_before_spawn", false);
        return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
    }
    pair_diag("writer_capability_before_spawn", true);
    let handoff = enrollment
        .take_bound_broker_handoff()
        .map_err(map_enrollment_error);
    pair_diag("writer_broker_handoff", handoff.is_ok());
    let handoff = handoff?;
    let mut launch_secret = Zeroizing::new([0; 32]);
    let mut launch_attempt = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut launch_secret[..]);
    rand::rngs::OsRng.fill_bytes(&mut launch_attempt);
    let action = enrollment.begun_action().map_err(map_enrollment_error)?;
    let (channel, relay, before, channel_binding, publication_key) = match action {
        runne_api::ProviderCredentialEnrollmentActionV2::Pair => {
            let launched = launch_verified_linux_pair_writer(
                handoff,
                &capability,
                stream,
                keys,
                *launch_secret,
            )
            .map_err(map_enrollment_error);
            pair_diag("writer_spawn_and_handshake", launched.is_ok());
            let (channel, relay, facts, binding, publication) = launched?;
            (channel, Some(relay), facts, binding, publication)
        }
        runne_api::ProviderCredentialEnrollmentActionV2::Revoke => {
            let launched = launch_verified_linux_control_writer(
                handoff,
                &capability,
                stream,
                keys,
                *launch_secret,
            )
            .map_err(map_enrollment_error);
            pair_diag("writer_spawn_and_handshake", launched.is_ok());
            let (channel, facts, binding, publication) = launched?;
            (channel, None, facts, binding, publication)
        }
        _ => return Err(runne_api::LaunchAuthorityError::UnsupportedPlatformBackend),
    };
    if !capability.revalidate_for_authenticated_desktop_peer(stream) {
        pair_diag("writer_post_spawn_revalidation", false);
        return reject_after_reap(channel, runne_api::LaunchAuthorityError::OwnershipMismatch);
    }
    let Some(after) = capability.measurement_facts(stream) else {
        pair_diag("writer_post_spawn_revalidation", false);
        return reject_after_reap(channel, runne_api::LaunchAuthorityError::OwnershipMismatch);
    };
    if !same_release(&before, &after) {
        pair_diag("writer_post_spawn_revalidation", false);
        return reject_after_reap(channel, runne_api::LaunchAuthorityError::OwnershipMismatch);
    }
    pair_diag("writer_post_spawn_revalidation", true);
    let measured_channel = channel.binding_digest().as_bytes();
    if measured_channel != channel_binding || publication_key == [0; 32] {
        pair_diag("writer_channel_binding", false);
        return reject_after_reap(channel, runne_api::LaunchAuthorityError::OwnershipMismatch);
    }
    pair_diag("writer_channel_binding", true);
    let writer = match channel.claim_process_facts() {
        Ok(writer) => {
            pair_diag("writer_process_claim_facts", true);
            writer
        }
        Err(error) => {
            pair_diag("writer_process_claim_facts", false);
            return reject_after_reap(channel, map_enrollment_error(error));
        }
    };
    let measurements = match enrollment.prepare_linux_claim_measurements(
        &after,
        writer,
        measured_channel,
        launch_attempt,
    ) {
        Ok(measurements) => {
            pair_diag("writer_claim_measurements", true);
            measurements
        }
        Err(error) => {
            pair_diag("writer_claim_measurements", false);
            return reject_after_reap(channel, map_enrollment_error(error));
        }
    };
    launch_attempt.zeroize();
    Ok(LinuxEnrollmentWriter {
        capability,
        installed: after,
        channel_binding,
        publication_key,
        channel: Some(channel),
        relay,
        claim_measurements: Some(measurements),
    })
}

fn reject_after_reap<T>(
    channel: LinuxCredentialBrokerChannel,
    error: runne_api::LaunchAuthorityError,
) -> Result<T, runne_api::LaunchAuthorityError> {
    channel
        .terminate_exact_writer()
        .map_err(map_enrollment_error)?;
    Err(error)
}

fn same_release(
    left: &VerifiedInstalledLinuxEnrollmentMeasurementFacts,
    right: &VerifiedInstalledLinuxEnrollmentMeasurementFacts,
) -> bool {
    left.desktop() == right.desktop()
        && left.writer() == right.writer()
        && left.daemon() == right.daemon()
        && left.contract() == right.contract()
        && left.candidate_source() == right.candidate_source()
        && left.target_manifest() == right.target_manifest()
        && left.release_tuple() == right.release_tuple()
        && left.qualification() == right.qualification()
        && left.installed_generation() == right.installed_generation()
}
