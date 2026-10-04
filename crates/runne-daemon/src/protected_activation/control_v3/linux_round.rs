use super::*;
use crate::application::provider_credential_enrollment::DaemonProtectedCredentialEnrollmentSession;
use crate::protected_activation::ProtectedActivationChannel;
use crate::protected_activation::linux_pair_diagnostics::record as pair_diag;
use runne_api::{ProtectedCredentialRoundBrokerFacts, ProtectedCredentialRoundCodec};
use runne_application::local_session::LocalSessionService;
use std::sync::{Arc, Mutex};

impl V3EnrollmentRuntime {
    pub(super) fn begin_next_linux_round(
        &mut self,
        channel: &mut ProtectedActivationChannel,
        keys: &ProtectedActivationKeys,
        owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        sessions: &Arc<Mutex<LocalSessionService>>,
        request: &[u8],
    ) -> Result<(), LaunchAuthorityError> {
        let previous = self
            .round_previous
            .as_ref()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        let control = self
            .linux_control
            .as_ref()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        let capability = self
            .linux_writer_capability
            .as_ref()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        if !self.terminal
            || self
                .linux_writer
                .as_ref()
                .is_some_and(runtime::LinuxEnrollmentWriter::in_flight)
            || !self.session.as_ref().is_some_and(has_completed_operation)
            || !linux_successor(previous, owned)
            || !capability_current(capability, channel, owned)
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        self.session
            .as_ref()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?
            .require_durable_terminal()
            .map_err(runtime::map_enrollment_error)?;
        let live = live_session::LiveEnrollmentSession::capture(sessions, owned)?;
        let mut codec = ProtectedCredentialRoundCodec::new(keys, owned);
        codec.decode_request(request)?;
        let rendezvous = crate::application::provider_credential_enrollment::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create()
            .map_err(runtime::map_enrollment_error)?;
        let facts = ProtectedCredentialRoundBrokerFacts::new(
            rendezvous.channel_binding(),
            rendezvous.publication_public_key(),
        )?;
        live.with_current(sessions, || Ok(()))?;
        channel.write_control_frame(&codec.encode_offer(facts)?)?;
        codec.decode_accept(&channel.read_control_frame()?)?;
        live.with_current(sessions, || Ok(()))?;
        if !capability_current(capability, channel, owned) {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let previous = self
            .session
            .take()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        let http_controls = previous.http_controls();
        previous.clear_http_facts();
        self.linux_writer.take();
        let session = control
            .start_protected_session_with_controls(keys, owned, rendezvous, http_controls)
            .map_err(runtime::map_enrollment_error)?;
        self.round_previous = Some(owned.clone());
        self.live = Some(live);
        self.session = Some(session);
        self.terminal = false;
        let request = request_next(channel)?;
        run_linux_initial_exchange(self, channel, keys, owned, sessions, request)
    }
}

pub(super) fn run_linux_initial_exchange(
    runtime: &mut V3EnrollmentRuntime,
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    _owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    sessions: &Arc<Mutex<LocalSessionService>>,
    request: zeroize::Zeroizing<Vec<u8>>,
) -> Result<(), LaunchAuthorityError> {
    let live = runtime
        .live
        .as_ref()
        .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
    let session = runtime
        .session
        .as_mut()
        .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
    let initial_result = initial_exchange::run(channel, session, live, sessions, request);
    pair_diag("begin_snapshot", initial_result.is_ok());
    initial_result?;
    runtime.terminal = session.require_durable_terminal().is_ok();
    if runtime.terminal {
        return Ok(());
    }
    let capability = runtime
        .linux_writer_capability
        .as_ref()
        .ok_or(LaunchAuthorityError::OwnershipMismatch)?
        .clone();
    let writer_result =
        runtime::launch_after_begin(session, capability, channel.unix_stream(), keys);
    pair_diag("writer_launch", writer_result.is_ok());
    let writer = writer_result?;
    runtime.linux_writer = Some(writer);
    let result = runtime
        .linux_writer
        .as_mut()
        .ok_or(LaunchAuthorityError::OwnershipMismatch)?
        .drive_claimed_writer(channel, sessions, keys, session, live);
    pair_diag("writer_claim_and_relay", result.is_ok());
    result?;
    runtime.terminal = true;
    Ok(())
}

fn request_next(
    channel: &mut ProtectedActivationChannel,
) -> Result<zeroize::Zeroizing<Vec<u8>>, LaunchAuthorityError> {
    channel.read_control_frame()
}

fn has_completed_operation(session: &DaemonProtectedCredentialEnrollmentSession) -> bool {
    !session.is_idle()
}

fn capability_current(
    capability: &runne_platform_desktop::VerifiedInstalledLinuxWriterCapability,
    channel: &ProtectedActivationChannel,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> bool {
    if !capability.revalidate_for_authenticated_desktop_peer(channel.unix_stream()) {
        return false;
    }
    capability
        .measurement_facts(channel.unix_stream())
        .is_some_and(|facts| {
            facts.release_tuple() == *owned.enrollment_binding().release_tuple_digest()
                && facts.qualification()
                    == *owned.enrollment_binding().qualification_binding_digest()
        })
}

fn linux_successor(
    previous: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    next: &ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> bool {
    previous.session_id() != next.session_id()
        && previous.launch_authority_id() == next.launch_authority_id()
        && previous.desktop_host_instance_id() == next.desktop_host_instance_id()
        && previous.daemon_instance_id() == next.daemon_instance_id()
        && previous.launch_generation() == next.launch_generation()
        && previous.stable() == next.stable()
        && previous.profile() == next.profile()
        && previous.executable() == next.executable()
        && previous.provider_binding() == next.provider_binding()
        && previous.enrollment_binding() == next.enrollment_binding()
}
