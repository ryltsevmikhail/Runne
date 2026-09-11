use super::{
    CredentialBrokerTransferAuthenticator, CredentialWriterHandoff, CredentialWriterHandoffError,
    CredentialWriterHandoffMode, EnrollmentBrokerFacts, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeProcess, ProviderCredentialBrokerHandoffContext,
    ProviderCredentialBrokerHandoffFrame, UnixStream, broker_offer, handoff_failure, unix_pair,
};
mod shared;
#[cfg(feature = "test-support")]
pub use shared::test_only_crossed_broker_offer;

fn trace_step(step: &str) {
    crate::provider_credential_broker::handoff_trace::step(step);
}

fn trace_step_failed(step: &str) {
    crate::provider_credential_broker::handoff_trace::step_failed(step);
}

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
    trace_step("endpoint-offer");
    control
        .offer(
            context,
            authenticator,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
        )
        .inspect_err(|_| trace_step_failed("endpoint-offer"))?;
    let (endpoint_half, endpoint_daemon_half) = unix_pair()?;
    trace_step("endpoint-respond");
    control
        .respond(&endpoint_daemon_half, facts.binding(), authenticator)
        .inspect_err(|_| trace_step_failed("endpoint-respond"))?;
    trace_step("endpoint-prepare");
    let prepared = crate::provider_credential_broker::prepare_daemon_owned_writer_endpoint_handoff(
        endpoint_half,
        authenticator,
        facts.binding(),
        facts.publication_public_key(),
    )
    .inspect_err(|_| trace_step_failed("endpoint-prepare"))
    .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    trace_step("writer-spawn");
    let (writer, pair_relay) = match mode {
        CredentialWriterHandoffMode::Pair => {
            let (writer, relay) = crate::provider_credential_broker::spawn_macos_verified_pair_writer_from_prepared_daemon_handoff(
                writer_launch,
                prepared,
            )
            .inspect_err(|_| trace_step_failed("writer-spawn"))
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
            (writer, Some(relay))
        }
        CredentialWriterHandoffMode::ControlOnly => (
            crate::provider_credential_broker::spawn_macos_verified_writer_from_prepared_daemon_handoff(
                writer_launch,
                prepared,
            )
            .inspect_err(|_| trace_step_failed("writer-spawn"))
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?,
            None,
        ),
    };
    // Writer ingress requires the transfer socket to retain a connected
    // peer until its inherited endpoint record has been consumed.
    drop(endpoint_daemon_half);

    // Purpose 2: offer the evidence transport and answer its challenge.
    trace_step("evidence-offer");
    control
        .offer(
            context,
            authenticator,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_EVIDENCE,
        )
        .inspect_err(|_| trace_step_failed("evidence-offer"))?;
    let (evidence_half, evidence_daemon_half) = unix_pair()?;
    trace_step("evidence-respond");
    control
        .respond(&evidence_daemon_half, facts.binding(), authenticator)
        .inspect_err(|_| trace_step_failed("evidence-respond"))?;
    trace_step("evidence-transfer");
    let pending = writer
        .transfer_evidence_to_daemon(evidence_half, authenticator)
        .inspect_err(|_| trace_step_failed("evidence-transfer"))
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;

    // Purpose 3: offer the kill transport and complete the fixed
    // Ready/Relinquished exchange before the daemon's acknowledgement.
    trace_step("kill-offer");
    let nonce = control
        .offer(
            context,
            authenticator,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
        )
        .inspect_err(|_| trace_step_failed("kill-offer"))?;
    let (kill_half, kill_daemon_half) = unix_pair()?;
    trace_step("kill-respond");
    control
        .respond(&kill_daemon_half, facts.binding(), authenticator)
        .inspect_err(|_| trace_step_failed("kill-respond"))?;
    trace_step("kill-complete");
    let outcome = pending
        .complete_daemon_kill_ownership(kill_half, authenticator)
        .inspect_err(|_| trace_step_failed("kill-complete"))
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    // A delivered acknowledgement proves the daemon read the relinquished
    // wire; a failed delivery with an acknowledgement is contradictory.
    trace_step("kill-delivery");
    let delivery = outcome
        .delivery_result()
        .inspect_err(|_| trace_step_failed("kill-delivery"))
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch);
    let handoff = CredentialWriterHandoff {
        owner: Some(outcome.into_reap_only_owner()),
        pair_relay,
    };
    trace_step("acknowledge");
    let result = delivery
        .and_then(|()| control.acknowledge(context, authenticator, nonce))
        .inspect_err(|_| trace_step_failed("acknowledge"));
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
