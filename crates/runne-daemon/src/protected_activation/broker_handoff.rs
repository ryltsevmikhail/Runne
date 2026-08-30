//! Broker writer-handoff dispatch mounted in the V3 enrollment control loop.
//!
//! The desktop drives three strictly ordered purposes over the already
//! authenticated channel: the writer endpoint transfer (`SCM_RIGHTS` of the
//! daemon-created rendezvous endpoint), the writer evidence, and the kill
//! exchange whose daemon acknowledgement is the final frame. Every mismatch
//! terminates the loop; the daemon never retries a consumed purpose.

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use runne_api::{
    CredentialBrokerTransferAuthenticator, LaunchAuthorityError, ProtectedActivationKeys,
    ProtectedCredentialEnrollmentOwnedLaunchV3, ProviderCredentialBrokerHandoffContext,
    ProviderCredentialBrokerHandoffFrame, ProviderCredentialBrokerTransferAuthority,
    is_broker_handoff_frame,
};
use runne_platform_desktop::provider_credential_broker::{
    ReceivedWriterProcessMeasurements, receive_daemon_control_transport_half,
    receive_daemon_owned_writer_measurements, send_daemon_owned_writer_endpoint,
};

#[cfg(target_os = "macos")]
use runne_platform_desktop::provider_credential_broker::{
    MacOsPeerKillCapability, capture_macos_daemon_peer_kill_capability,
};

use super::{
    ProtectedActivationChannel, enrollment_control_transition::DaemonEnrollmentRendezvous,
};

pub(crate) type HandoffTicketClock =
    Arc<dyn Fn() -> Result<u64, LaunchAuthorityError> + Send + Sync>;

/// One-shot broker handoff state owned by the V3 control loop.
pub(crate) struct BrokerHandoffDispatch {
    authenticator: CredentialBrokerTransferAuthenticator,
    authority: Option<ProviderCredentialBrokerTransferAuthority>,
    context: ProviderCredentialBrokerHandoffContext,
    rendezvous: DaemonEnrollmentRendezvous,
    binding: [u8; 32],
    publication_public_key: [u8; 32],
    release_tuple: [u8; 32],
    purposes_left: Vec<u8>,
    offer: Option<ProviderCredentialBrokerHandoffFrame>,
    measurements: Option<ReceivedWriterProcessMeasurements>,
    #[cfg(target_os = "macos")]
    kill: Option<MacOsPeerKillCapability>,
}

impl BrokerHandoffDispatch {
    /// Binds the dispatch to the exact V3 launch and transition rendezvous.
    pub(crate) fn new(
        keys: &ProtectedActivationKeys,
        owned_launch: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        rendezvous: DaemonEnrollmentRendezvous,
    ) -> Result<Self, LaunchAuthorityError> {
        let binding = rendezvous.broker_authority().channel_binding();
        let publication_public_key = rendezvous.broker_authority().publication_public_key();
        let context = ProviderCredentialBrokerHandoffContext::new(
            *owned_launch.stable().authority_id(),
            *owned_launch.session_id(),
            owned_launch.launch_generation(),
            binding,
        )?;
        Ok(Self {
            authenticator: CredentialBrokerTransferAuthenticator::from_protected_activation(keys),
            authority: Some(
                ProviderCredentialBrokerTransferAuthority::from_enrollment_launch_keys(
                    keys,
                    owned_launch
                        .enrollment_binding()
                        .broker_transfer_commitment(),
                ),
            ),
            context,
            binding,
            publication_public_key,
            release_tuple: *owned_launch.enrollment_binding().release_tuple_digest(),
            purposes_left: vec![
                ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
                ProviderCredentialBrokerHandoffFrame::PURPOSE_EVIDENCE,
                ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
            ],
            offer: None,
            measurements: None,
            #[cfg(target_os = "macos")]
            kill: None,
            rendezvous,
        })
    }

    /// Consumes one broker handoff offer, or reports the frame is not one.
    ///
    /// Any decode, freshness, purpose-order, binding, or raw-phase failure is
    /// returned and terminates the control loop fail-closed.
    pub(crate) fn dispatch(
        &mut self,
        channel: &mut ProtectedActivationChannel,
        frame: &[u8],
        ticket_clock: &HandoffTicketClock,
    ) -> Result<bool, LaunchAuthorityError> {
        if !is_broker_handoff_frame(frame) {
            return Ok(false);
        }
        let Some((purpose, rest)) = self.purposes_left.split_first() else {
            return Err(LaunchAuthorityError::InvalidContract);
        };
        let (purpose, rest) = (*purpose, rest.to_vec());
        let now = ticket_clock()?;
        let offer = ProviderCredentialBrokerHandoffFrame::decode_and_verify(
            frame,
            &self.authenticator,
            &self.context,
            ProviderCredentialBrokerHandoffFrame::PHASE_OFFER,
            purpose,
            [0; 16],
            now,
        )?;
        channel.write_control_frame(&offer.ready(&self.authenticator).encode_frame())?;
        self.offer = Some(offer);
        self.run_purpose(purpose, channel)?;
        self.purposes_left = rest;
        Ok(true)
    }

    /// Exact writer kill authority retained after the desktop relinquished.
    #[cfg(target_os = "macos")]
    pub(crate) fn take_kill(&mut self) -> Option<MacOsPeerKillCapability> {
        self.kill.take()
    }

    fn run_purpose(
        &mut self,
        purpose: u8,
        channel: &mut ProtectedActivationChannel,
    ) -> Result<(), LaunchAuthorityError> {
        match purpose {
            ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT => {
                let half = self.receive_half(channel)?;
                let writer = self
                    .rendezvous
                    .take_writer_endpoint()
                    .ok_or(LaunchAuthorityError::InvalidContract)?;
                send_daemon_owned_writer_endpoint(
                    half,
                    writer,
                    self.author()?,
                    self.binding,
                    self.publication_public_key,
                )
                .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
            }
            ProviderCredentialBrokerHandoffFrame::PURPOSE_EVIDENCE => {
                let half = self.receive_half(channel)?;
                let authority = self
                    .authority
                    .take()
                    .ok_or(LaunchAuthorityError::InvalidContract)?;
                let (measurements, authority) = receive_daemon_owned_writer_measurements(
                    half,
                    authority,
                    self.release_tuple,
                    self.binding,
                    self.publication_public_key,
                )
                .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
                if !measurements.matches_daemon_owned_release(
                    self.release_tuple,
                    self.binding,
                    self.publication_public_key,
                ) {
                    return Err(LaunchAuthorityError::OwnershipMismatch);
                }
                self.authority = Some(authority);
                self.measurements = Some(measurements);
            }
            ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL => self.run_kill_purpose(channel)?,
            _ => return Err(LaunchAuthorityError::InvalidContract),
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn run_kill_purpose(
        &mut self,
        channel: &mut ProtectedActivationChannel,
    ) -> Result<(), LaunchAuthorityError> {
        let half = self.receive_half(channel)?;
        let measurements = self
            .measurements
            .take()
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        let pending = capture_macos_daemon_peer_kill_capability(
            self.rendezvous.broker_authority().endpoint(),
            measurements,
            self.author()?,
        )
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
        let capability = pending
            .complete_desktop_relinquishment(half, self.author()?)
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
        let acknowledgement = self
            .offer
            .take()
            .ok_or(LaunchAuthorityError::InvalidContract)?
            .acknowledgement(&self.authenticator);
        channel.write_control_frame(&acknowledgement.encode_frame())?;
        self.kill = Some(capability);
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn run_kill_purpose(
        &mut self,
        _channel: &mut ProtectedActivationChannel,
    ) -> Result<(), LaunchAuthorityError> {
        Err(LaunchAuthorityError::UnsupportedPlatformBackend)
    }

    fn author(&self) -> Result<&ProviderCredentialBrokerTransferAuthority, LaunchAuthorityError> {
        self.authority
            .as_ref()
            .ok_or(LaunchAuthorityError::InvalidContract)
    }

    /// Receives exactly one offered daemon-owned half over the channel clone.
    fn receive_half(
        &self,
        channel: &mut ProtectedActivationChannel,
    ) -> Result<UnixStream, LaunchAuthorityError> {
        let mut stream = channel
            .unix_stream()
            .try_clone()
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        receive_daemon_control_transport_half(&mut stream, self.author()?, self.binding)
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)
    }
}
