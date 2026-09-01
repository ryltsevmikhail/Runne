//! Broker writer-handoff dispatch mounted in the V3 enrollment control loop.
//!
//! The desktop drives three strictly ordered purposes over the already
//! authenticated channel: the writer endpoint transfer (`SCM_RIGHTS` of the
//! daemon-created rendezvous endpoint), the writer evidence, and the kill
//! exchange whose daemon acknowledgement is the final frame. Every mismatch
//! terminates the loop; the daemon never retries a consumed purpose.

use std::sync::Arc;

mod dispatch;

use runne_api::{
    CredentialBrokerTransferAuthenticator, LaunchAuthorityError, ProtectedActivationKeys,
    ProtectedCredentialEnrollmentOwnedLaunchV3, ProviderCredentialBrokerHandoffContext,
    ProviderCredentialBrokerHandoffFrame, ProviderCredentialBrokerTransferAuthority,
    is_broker_handoff_frame,
};
use runne_platform_desktop::provider_credential_broker::ReceivedWriterProcessMeasurements;
use sha2::{Digest as _, Sha256};

#[cfg(target_os = "macos")]
use runne_platform_desktop::provider_credential_broker::MacOsPeerKillCapability;

use super::{
    ProtectedActivationChannel, enrollment_control_transition::DaemonEnrollmentRendezvous,
};
use crate::application::provider_credential_enrollment::broker::{
    AwaitingVerifiedWriter, PendingBrokerEndpointHandoff,
    VerifiedMacOsWriterWithDaemonKillCapability, VerifiedWriterAwaitingDaemonKillCapability,
};

pub(crate) type HandoffTicketClock =
    Arc<dyn Fn() -> Result<u64, LaunchAuthorityError> + Send + Sync>;

/// One-shot broker handoff state owned by the V3 control loop.
pub(crate) struct BrokerHandoffDispatch {
    authenticator: CredentialBrokerTransferAuthenticator,
    authority: Option<ProviderCredentialBrokerTransferAuthority>,
    context: ProviderCredentialBrokerHandoffContext,
    rendezvous: Option<DaemonEnrollmentRendezvous>,
    bound_endpoint: Option<PendingBrokerEndpointHandoff>,
    bound_writer: Option<AwaitingVerifiedWriter>,
    verified_writer: Option<VerifiedWriterAwaitingDaemonKillCapability>,
    expected_operation: Option<runne_provider::CredentialOperationId>,
    launch_attempt: Option<[u8; 32]>,
    binding: [u8; 32],
    publication_public_key: [u8; 32],
    release_tuple: [u8; 32],
    purposes_left: Vec<u8>,
    offer: Option<ProviderCredentialBrokerHandoffFrame>,
    measurements: Option<ReceivedWriterProcessMeasurements>,
    #[cfg(target_os = "macos")]
    kill: Option<MacOsPeerKillCapability>,
    #[cfg(target_os = "macos")]
    bound_kill: Option<VerifiedMacOsWriterWithDaemonKillCapability>,
}

impl BrokerHandoffDispatch {
    /// Binds the dispatch to the exact V3 launch and transition rendezvous.
    pub(crate) fn new(
        keys: &ProtectedActivationKeys,
        owned_launch: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        mut rendezvous: DaemonEnrollmentRendezvous,
    ) -> Result<Self, LaunchAuthorityError> {
        let binding = rendezvous.channel_binding()?;
        let publication_public_key = rendezvous.publication_public_key()?;
        rendezvous.prepare_dispatch()?;
        let mut dispatch = Self::from_facts(keys, owned_launch, binding, publication_public_key)?;
        #[cfg(test)]
        {
            dispatch.expected_operation = Some(
                runne_provider::CredentialOperationId::from_bytes([0xA5; 16])
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            );
        }
        dispatch.rendezvous = Some(rendezvous);
        Ok(dispatch)
    }

    pub(crate) fn from_bound_enrollment(
        keys: &ProtectedActivationKeys,
        owned_launch: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        endpoint: PendingBrokerEndpointHandoff,
    ) -> Result<Self, LaunchAuthorityError> {
        let (binding, publication_public_key) = endpoint.rendezvous_facts();
        let operation_id = endpoint.operation_id();
        let mut dispatch = Self::from_facts(keys, owned_launch, binding, publication_public_key)?;
        dispatch.bound_endpoint = Some(endpoint);
        dispatch.expected_operation = Some(operation_id);
        Ok(dispatch)
    }

    fn from_facts(
        keys: &ProtectedActivationKeys,
        owned_launch: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        binding: [u8; 32],
        publication_public_key: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
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
            #[cfg(target_os = "macos")]
            bound_kill: None,
            rendezvous: None,
            bound_endpoint: None,
            bound_writer: None,
            verified_writer: None,
            expected_operation: None,
            launch_attempt: None,
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
        if purpose == ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT {
            let operation = self
                .expected_operation
                .ok_or(LaunchAuthorityError::InvalidContract)?;
            let mut launch = Sha256::new();
            launch.update(b"gocode/provider-credential-enrollment/writer-launch-attempt/v1\0");
            launch.update(frame);
            launch.update(operation.as_bytes());
            self.launch_attempt = Some(launch.finalize().into());
        }
        channel.write_control_frame(&offer.ready(&self.authenticator).encode_frame())?;
        self.offer = Some(offer);
        self.run_purpose(purpose, channel)?;
        self.purposes_left = rest;
        Ok(true)
    }

    /// Terminates only the exact writer authority retained after desktop ACK.
    #[cfg(target_os = "macos")]
    pub(crate) fn terminate_retained_writer(&mut self) {
        if let Some(writer) = self.bound_kill.take() {
            let _ = writer.terminate_exact_writer();
        }
        if let Some(kill) = self.kill.take() {
            let _ = kill.terminate_exact_peer();
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn verified_writer_facts(
        &self,
    ) -> Option<&runne_platform_desktop::provider_credential_broker::VerifiedWriterMeasurementFacts>
    {
        self.bound_kill
            .as_ref()
            .map(VerifiedMacOsWriterWithDaemonKillCapability::verified_measurement_facts)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn verified_writer_launch_attempt(&self) -> Option<[u8; 32]> {
        self.bound_kill.as_ref()?;
        self.launch_attempt
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn take_verified_writer(
        &mut self,
    ) -> Option<VerifiedMacOsWriterWithDaemonKillCapability> {
        self.bound_kill.take()
    }
}
