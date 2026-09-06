use super::*;
use crate::application::provider_credential_enrollment::{
    DaemonProviderCredentialEnrollmentControl, broker::rendezvous::DaemonOwnedUnixBrokerRendezvous,
};

pub(super) struct RoundProfile {
    directory: std::path::PathBuf,
    installation: [u8; 32],
}

impl V3EnrollmentDispatch {
    pub(crate) fn with_round_profile(
        mut self,
        directory: std::path::PathBuf,
        installation: &crate::protected_activation::installation_anchor::VerifiedNativeEnrollmentInstallation,
    ) -> Self {
        self.round_profile = Some(RoundProfile {
            directory,
            installation: *installation.installation_identity_digest(),
        });
        self
    }
}

pub(super) struct RoundContext {
    pub(super) profile: RoundProfile,
    pub(super) control: Arc<DaemonProviderCredentialEnrollmentControl>,
    pub(super) previous: ProtectedCredentialEnrollmentOwnedLaunchV3,
}

impl V3EnrollmentRuntime {
    pub(super) fn begin_next_round(
        &mut self,
        channel: &mut ProtectedActivationChannel,
        keys: &ProtectedActivationKeys,
        owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        sessions: &Mutex<LocalSessionService>,
        request: &[u8],
    ) -> Result<(), LaunchAuthorityError> {
        let context = self
            .round
            .as_ref()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        if !self.terminal
            || self.channel.is_some()
            || self.claim_measurements.is_some()
            || self
                .broker
                .as_ref()
                .is_some_and(|broker| broker.verified_writer_facts().is_some())
            || !context.profile.directory.is_absolute()
            || context.profile.installation
                != *owned.enrollment_binding().installation_identity_digest()
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        require_successor(&context.previous, owned)?;
        self.session
            .as_ref()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?
            .require_durable_terminal()
            .map_err(runtime::map_enrollment_error)?;
        let live = live_session::LiveEnrollmentSession::capture(sessions, owned)?;
        let mut codec = runne_api::ProtectedCredentialRoundCodec::new(keys, owned);
        codec.decode_request(request)?;
        runne_platform_desktop::VerifiedDaemonNativeEnrollmentPrepare::verify_and_measure_current_v3_peer(
            &context.profile.directory, owned, channel.unix_stream(),
        ).ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        let rendezvous =
            DaemonOwnedUnixBrokerRendezvous::create().map_err(runtime::map_enrollment_error)?;
        let facts = runne_api::ProtectedCredentialRoundBrokerFacts::new(
            rendezvous.channel_binding(),
            rendezvous.publication_public_key(),
        )?;
        live.with_current(sessions, || Ok(()))?;
        channel.write_control_frame(&codec.encode_offer(facts)?)?;
        codec.decode_accept(&channel.read_control_frame()?)?;
        live.with_current(sessions, || Ok(()))?;
        let installed = runne_platform_desktop::VerifiedDaemonNativeEnrollmentPrepare::verify_and_measure_current_v3_peer(
            &context.profile.directory, owned, channel.unix_stream(),
        ).ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        let configuration = installed.runtime_credential_service_configuration();
        let service = crate::protected_activation::credential_service_registration::receive_required_registration(
            channel, keys, owned, &installed, runtime::unix_now_millis()?,
        )?.map(|session| context.control.install_credential_service_session(session))
            .transpose().map_err(runtime::map_enrollment_error)?;
        let mut session = context
            .control
            .start_protected_session(keys, owned, rendezvous, installed)
            .map_err(runtime::map_enrollment_error)?;
        let request = channel.read_control_frame()?;
        initial_exchange::run(channel, &mut session, &live, sessions, request)?;
        let terminal = session.begun_is_terminal();
        let broker = runtime::bind_broker(keys, owned, &mut session)?;
        self.session = Some(session);
        self.broker = broker;
        self.live = Some(live);
        self.terminal = terminal;
        self.credential_service = service;
        self.credential_service_configuration = configuration;
        self.round
            .as_mut()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?
            .previous = owned.clone();
        Ok(())
    }
}

fn require_successor(
    previous: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    next: &ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> Result<(), LaunchAuthorityError> {
    if previous.session_id() == next.session_id()
        || previous.launch_authority_id() != next.launch_authority_id()
        || previous.desktop_host_instance_id() != next.desktop_host_instance_id()
        || previous.daemon_instance_id() != next.daemon_instance_id()
        || previous.launch_generation() != next.launch_generation()
        || previous.stable() != next.stable()
        || previous.profile() != next.profile()
        || previous.executable() != next.executable()
        || previous.provider_binding() != next.provider_binding()
        || previous.enrollment_binding() != next.enrollment_binding()
    {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
