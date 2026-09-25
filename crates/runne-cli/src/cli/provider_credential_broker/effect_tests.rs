use runne_provider::CredentialOperationAction;

#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "macos")]
use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServicePortFuture, CredentialServiceWriterPort,
    CredentialServiceWriterReply, CredentialServiceWriterRequest,
};
#[cfg(target_os = "macos")]
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialEnrollmentAuthorityPair,
    CredentialMutationGrant, CredentialRuntimeMutationPlan, CredentialServiceCorrelation,
    CredentialServiceDeadline, CredentialServiceEpoch, CredentialServiceProtocolCodec,
    CredentialServiceReply, CredentialServiceRequestSequence, CredentialWriterAuthorityPair,
    sealed_pair_for_test,
};

use super::effect::{execute_non_pair_effect, execute_pair_effect};
use super::effect_test_support::{
    EffectCall, assert_frames, claimed, claimed_with_diagnostic_failure, pair_authorized,
    pair_authorized_with_diagnostic_failure,
};

#[test]
fn pair_effect_invokes_sealed_writer_and_observes_its_result() {
    for succeeds in [true, false] {
        let fixture = pair_authorized(succeeds);

        assert_eq!(execute_pair_effect(fixture.authority).is_ok(), succeeds);
        assert_eq!(*fixture.calls.lock().expect("calls"), vec![EffectCall::Create]);
        assert_frames(&fixture.written, succeeds);
    }
}

#[test]
fn pair_diagnostic_failure_closes_after_native_writer_invocation() {
    let fixture = pair_authorized_with_diagnostic_failure();

    assert!(execute_pair_effect(fixture.authority).is_err());
    assert_eq!(*fixture.calls.lock().expect("calls"), vec![EffectCall::Create]);
    assert_frames(&fixture.written, false);
}

#[test]
fn non_pair_effects_dispatch_exact_writer_input_and_observe_native_result() {
    for (action, expected, succeeds) in [
        (
            CredentialOperationAction::Revoke,
            EffectCall::Delete,
            false,
        ),
        (
            CredentialOperationAction::RetiredVersionCleanup,
            EffectCall::Delete,
            false,
        ),
        (
            CredentialOperationAction::MigrateLegacy,
            EffectCall::ImportLegacy,
            true,
        ),
        (
            CredentialOperationAction::LegacySourceCleanup,
            EffectCall::DeleteLegacySource,
            true,
        ),
    ] {
        let fixture = claimed(action);
        let authority = fixture
            .claimed
            .authorize_without_secret()
            .expect("non-pair authority");

        assert_eq!(execute_non_pair_effect(authority).is_ok(), succeeds);
        assert_eq!(*fixture.calls.lock().expect("calls"), vec![expected]);
        assert_frames(&fixture.written, succeeds);
    }
}

#[test]
fn diagnostic_write_failure_closes_after_native_invocation() {
    let fixture = claimed_with_diagnostic_failure(CredentialOperationAction::MigrateLegacy);
    let authority = fixture
        .claimed
        .authorize_without_secret()
        .expect("non-pair authority");

    assert!(execute_non_pair_effect(authority).is_err());
    assert_eq!(
        *fixture.calls.lock().expect("calls"),
        vec![EffectCall::ImportLegacy]
    );
    assert_frames(&fixture.written, false);
}

#[test]
#[cfg(target_os = "macos")]
fn service_pair_consumes_the_authenticated_handoff_through_writer_only_port() {
    let command = super::effect_test_support::command(CredentialOperationAction::Pair);
    let binding = CredentialBindingDigest::from_measured([13; 32]).unwrap();
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([11; 32]).unwrap();
    let sealed = sealed_pair_for_test(&command, binding, &channel, b"credential".to_vec()).unwrap();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let pending_claim = issuer.issue_pending_claim(&command, binding, &channel);
    let authorization = issuer
        .claim_accepted(
            pending_claim,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            binding,
            &channel,
        )
        .unwrap();
    let handoff = service_handoff(command);
    let port = ConsumingWriterPort(AtomicBool::new(false));

    super::effect::consume_service_pair_with_port(
        &port,
        &effects,
        handoff,
        authorization,
        &channel,
        binding,
        sealed.pending,
        sealed.envelope,
    )
    .unwrap();

    assert!(port.0.load(Ordering::SeqCst));
}

#[test]
#[cfg(target_os = "macos")]
fn service_revoke_consumes_a_secretless_authenticated_handoff() {
    let command = super::effect_test_support::command(CredentialOperationAction::Revoke);
    let binding = CredentialBindingDigest::from_measured([13; 32]).unwrap();
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([11; 32]).unwrap();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let pending = issuer.issue_pending_claim(&command, binding, &channel);
    let authorization = issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            binding,
            &channel,
        )
        .unwrap();
    let handoff = service_handoff(command);
    let port = ConsumingWriterPort(AtomicBool::new(false));

    super::effect::consume_service_control_with_port(
        &port,
        &effects,
        handoff,
        authorization,
        &channel,
        binding,
    )
    .unwrap();

    assert!(port.0.load(Ordering::SeqCst));
}

#[cfg(target_os = "macos")]
fn service_handoff(
    command: runne_provider::CredentialBrokerCommand,
) -> runne_provider::CredentialWriterBrokerHandoffFrame {
    let grant = CredentialMutationGrant::generate().unwrap();
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let plan = CredentialRuntimeMutationPlan::issue(
        &store.runtime_arm_authority(),
        command,
        CredentialServiceEpoch::from_bytes([2; 16]).unwrap(),
        [3; 32],
        [4; 16],
        5,
        CredentialBindingDigest::from_measured([6; 32]).unwrap(),
        CredentialServiceRequestSequence::new(1).unwrap(),
        CredentialServiceCorrelation::from_bytes([7; 16]).unwrap(),
        CredentialServiceDeadline::new(10, 20).unwrap(),
        grant.digest(),
    )
    .unwrap();
    let (_, writer) = plan.split();
    CredentialServiceProtocolCodec::encode_writer_broker_handoff(writer, grant).unwrap()
}

#[cfg(target_os = "macos")]
struct ConsumingWriterPort(AtomicBool);

#[cfg(target_os = "macos")]
impl CredentialServiceWriterPort for ConsumingWriterPort {
    fn consume_mutation(
        &self,
        request: CredentialServiceWriterRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceWriterReply> {
        self.0.store(true, Ordering::SeqCst);
        let reply = request.with_bytes(|bytes| {
            let request = CredentialServiceProtocolCodec::decode_writer_request(bytes).unwrap();
            CredentialServiceProtocolCodec::encode_reply(
                request.context(),
                CredentialServiceReply::Consumed,
            )
            .unwrap()
        });
        Box::pin(async move {
            CredentialServiceWriterReply::from_zeroizing(reply.into_transport_bytes())
        })
    }
}
