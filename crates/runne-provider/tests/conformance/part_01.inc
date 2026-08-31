use futures::executor::block_on;
use runne_provider::{
    CancelDisposition, CancelRequest, DispatchAttemptId, DispatchRequest, DispatchRequestError,
    ModelRef, PrepareError, ProviderCall, ProviderCallDigestVersion, ProviderCallId,
    ProviderCapability, ProviderDispatchClaim, ProviderFinishReason, ProviderId, ProviderPort,
    ProviderStreamEvent, ProviderStreamEventKind, ProviderTerminalDisposition, ProviderUsage,
    ReconcileRequest, ReconciliationDisposition, ScriptedProvider, StreamCursor, StreamError,
};

fn call(required: Vec<ProviderCapability>) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([1; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-28",
        )
        .unwrap(),
        [2; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap()
    .with_required_capabilities(required)
}

fn dispatch_request(
    prepared: runne_provider::PreparedRequest,
    attempt_id: DispatchAttemptId,
    provider_idempotency_key: &str,
) -> DispatchRequest {
    let claim = ProviderDispatchClaim {
        provider_id: prepared.call().model_ref().provider_id().clone(),
        call_id: prepared.call().call_id(),
        attempt_id,
        permit_id: [4; 16],
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [6; 32],
        token_reservation_id: [7; 16],
        cost_reservation_id: [8; 16],
        fencing_token: 1,
        provider_idempotency_key: provider_idempotency_key.to_owned(),
    };
    DispatchRequest::new(prepared, claim).unwrap()
}

fn successful_script() -> Vec<ProviderStreamEvent> {
    vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "hello".to_owned(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(
            2,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        )
        .unwrap(),
    ]
}

#[test]
fn one_usage_event_is_valid_before_terminal_completion() {
    let script = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(10, 5, 2, 1).unwrap(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(
            2,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        )
        .unwrap(),
    ];

    assert!(ScriptedProvider::new([ProviderCapability::Streaming], script).is_ok());
}

#[test]
fn scripted_stream_rejects_duplicate_usage() {
    let usage = ProviderUsage::new(10, 5, 2, 1).unwrap();
    let script = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(1, ProviderStreamEventKind::Usage { usage }).unwrap(),
        ProviderStreamEvent::new(2, ProviderStreamEventKind::Usage { usage }).unwrap(),
        ProviderStreamEvent::new(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        )
        .unwrap(),
    ];

    assert!(ScriptedProvider::new([ProviderCapability::Streaming], script).is_err());
}

#[test]
fn usage_unavailable_is_typed_and_conflicts_with_exact_usage() {
    let event = ProviderStreamEvent::new(1, ProviderStreamEventKind::UsageUnavailable).unwrap();
    let encoded = serde_json::to_vec(&event).unwrap();
    assert_eq!(
        serde_json::from_slice::<ProviderStreamEvent>(&encoded).unwrap(),
        event
    );

    let usage = ProviderUsage::new(10, 5, 2, 1).unwrap();
    let script = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        event,
        ProviderStreamEvent::new(2, ProviderStreamEventKind::Usage { usage }).unwrap(),
    ];
    assert!(ScriptedProvider::new([ProviderCapability::Streaming], script).is_err());
}

#[test]
fn scripted_stream_rejects_duplicate_start() {
    let script = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(1, ProviderStreamEventKind::Started).unwrap(),
    ];

    assert!(ScriptedProvider::new([ProviderCapability::Streaming], script).is_err());
}

#[test]
fn scripted_stream_rejects_events_after_terminal() {
    let script = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(
            2,
            ProviderStreamEventKind::TextDelta {
                text: "late".to_owned(),
            },
        )
        .unwrap(),
    ];

    assert!(ScriptedProvider::new([ProviderCapability::Streaming], script).is_err());
}

#[test]
fn scripted_stream_rejects_payload_before_started() {
    let script = vec![
        ProviderStreamEvent::new(
            0,
            ProviderStreamEventKind::TextDelta {
                text: "early".to_owned(),
            },
        )
        .unwrap(),
    ];

    assert!(ScriptedProvider::new([ProviderCapability::Streaming], script).is_err());
}
