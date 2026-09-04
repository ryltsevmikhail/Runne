use super::{
    CredentialBrokerTransferAuthenticator, CredentialWriterHandoff, CredentialWriterHandoffError,
    CredentialWriterHandoffMode, EnrollmentBrokerFacts, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeProcess, ProviderCredentialBrokerHandoffContext,
    ProviderCredentialBrokerHandoffFrame, UnixStream, broker_offer, handoff_failure, unix_pair,
};
mod shared;
#[cfg(feature = "test-support")]
pub use shared::test_only_crossed_broker_offer;

pub(super) trait BrokerControl {
    fn offer(
        &mut self,
        context: &ProviderCredentialBrokerHandoffContext,
        authenticator: &CredentialBrokerTransferAuthenticator,
        purpose: u8,
    ) -> Result<[u8; 16], ProtectedBundledRuntimeError>;
    fn respond(
        &mut self,
        daemon_half: &UnixStream,
        binding: [u8; 32],
        authenticator: &CredentialBrokerTransferAuthenticator,
    ) -> Result<(), ProtectedBundledRuntimeError>;
    fn acknowledge(
        &mut self,
        context: &ProviderCredentialBrokerHandoffContext,
        authenticator: &CredentialBrokerTransferAuthenticator,
        nonce: [u8; 16],
    ) -> Result<(), ProtectedBundledRuntimeError>;
}

// Native writer state stays on this calling thread across all control exchanges.
pub(super) fn drive(
    control: &mut impl BrokerControl,
    writer_launch: crate::VerifiedMacOsWriterLaunch,
    mode: CredentialWriterHandoffMode,
    facts: EnrollmentBrokerFacts,
    authenticator: &CredentialBrokerTransferAuthenticator,
    context: &ProviderCredentialBrokerHandoffContext,
) -> Result<CredentialWriterHandoff, CredentialWriterHandoffError> {
    // Purpose 1: offer the daemon half of the endpoint transport, answer
    // the challenge, and spawn the fixed writer with the desktop half.
    control.offer(
        context,
        authenticator,
        ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
    )?;
    let (endpoint_half, endpoint_daemon_half) = unix_pair()?;
    control.respond(&endpoint_daemon_half, facts.binding(), authenticator)?;
    let prepared = crate::provider_credential_broker::prepare_daemon_owned_writer_endpoint_handoff(
        endpoint_half,
        authenticator,
        facts.binding(),
        facts.publication_public_key(),
    )
    .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    let (writer, pair_relay) = match mode {
        CredentialWriterHandoffMode::Pair => {
            let (writer, relay) = crate::provider_credential_broker::spawn_macos_verified_pair_writer_from_prepared_daemon_handoff(
                writer_launch,
                prepared,
            )
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
            (writer, Some(relay))
        }
        CredentialWriterHandoffMode::ControlOnly => (
            crate::provider_credential_broker::spawn_macos_verified_writer_from_prepared_daemon_handoff(
                writer_launch,
                prepared,
            )
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?,
            None,
        ),
    };
    // Writer ingress requires the transfer socket to retain a connected
    // peer until its inherited endpoint record has been consumed.
    drop(endpoint_daemon_half);

    // Purpose 2: offer the evidence transport and answer its challenge.
    control.offer(
        context,
        authenticator,
        ProviderCredentialBrokerHandoffFrame::PURPOSE_EVIDENCE,
    )?;
    let (evidence_half, evidence_daemon_half) = unix_pair()?;
    control.respond(&evidence_daemon_half, facts.binding(), authenticator)?;
    let pending = writer
        .transfer_evidence_to_daemon(evidence_half, authenticator)
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;

    // Purpose 3: offer the kill transport and complete the fixed
    // Ready/Relinquished exchange before the daemon's acknowledgement.
    let nonce = control.offer(
        context,
        authenticator,
        ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
    )?;
    let (kill_half, kill_daemon_half) = unix_pair()?;
    control.respond(&kill_daemon_half, facts.binding(), authenticator)?;
    let outcome = pending
        .complete_daemon_kill_ownership(kill_half, authenticator)
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    // A delivered acknowledgement proves the daemon read the relinquished
    // wire; a failed delivery with an acknowledgement is contradictory.
    let delivery = outcome
        .delivery_result()
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch);
    let handoff = CredentialWriterHandoff {
        owner: Some(outcome.into_reap_only_owner()),
        pair_relay,
    };
    let result = delivery.and_then(|()| control.acknowledge(context, authenticator, nonce));
    handoff_failure::finish(handoff, result)
}

impl BrokerControl for ProtectedBundledRuntimeProcess {
    fn offer(
        &mut self,
        context: &ProviderCredentialBrokerHandoffContext,
        authenticator: &CredentialBrokerTransferAuthenticator,
        purpose: u8,
    ) -> Result<[u8; 16], ProtectedBundledRuntimeError> {
        self.offer_broker_transport(context, authenticator, purpose)
    }
    fn respond(
        &mut self,
        daemon_half: &UnixStream,
        binding: [u8; 32],
        authenticator: &CredentialBrokerTransferAuthenticator,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        self.respond_transport_offer(daemon_half, binding, authenticator)
    }
    fn acknowledge(
        &mut self,
        context: &ProviderCredentialBrokerHandoffContext,
        authenticator: &CredentialBrokerTransferAuthenticator,
        nonce: [u8; 16],
    ) -> Result<(), ProtectedBundledRuntimeError> {
        broker_offer::receive(
            &mut self.channel,
            context,
            authenticator,
            ProviderCredentialBrokerHandoffFrame::PHASE_ACK,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
            nonce,
            || {
                crate::MacOsContinuousClock::now_millis()
                    .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)
            },
        )
    }
}
