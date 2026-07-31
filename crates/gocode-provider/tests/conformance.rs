use futures::executor::block_on;
use gocode_provider::{
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
    prepared: gocode_provider::PreparedRequest,
    attempt_id: DispatchAttemptId,
    provider_idempotency_key: &str,
) -> DispatchRequest {
    let claim = ProviderDispatchClaim {
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

#[test]
fn normalized_stream_payloads_are_bounded_and_closed_before_runtime_journaling() {
    assert!(
        ProviderStreamEvent::new(
            0,
            ProviderStreamEventKind::TextDelta {
                text: String::new(),
            },
        )
        .is_err()
    );
    assert!(
        ProviderStreamEvent::new(
            0,
            ProviderStreamEventKind::TextDelta {
                text: "x".repeat(gocode_provider::MAX_PROVIDER_TEXT_DELTA_BYTES + 1),
            },
        )
        .is_err()
    );
    assert!(
        ProviderStreamEvent::new(
            0,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call-1".into(),
                tool_name: "process.exec".into(),
                arguments_json: "{invalid".into(),
            },
        )
        .is_err()
    );
    assert!(
        ProviderStreamEvent::new(
            0,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call\n1".into(),
                tool_name: "process.exec".into(),
                arguments_json: "{}".into(),
            },
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<ProviderStreamEvent>(serde_json::json!({
            "sequence": 0,
            "kind": {
                "kind": "text_delta",
                "text": "x".repeat(gocode_provider::MAX_PROVIDER_TEXT_DELTA_BYTES + 1)
            }
        }))
        .is_err()
    );
}

#[test]
fn prepare_is_deterministic_and_has_no_dispatch_effect() {
    let adapter =
        ScriptedProvider::new([ProviderCapability::Streaming], successful_script()).unwrap();
    let provider_call = call(vec![ProviderCapability::Streaming]);

    let left = adapter.prepare(&provider_call).unwrap();
    let right = adapter.prepare(&provider_call).unwrap();

    assert_eq!(left, right);
    assert_eq!(
        left.request_ref().digest_version(),
        ProviderCallDigestVersion::V2
    );
    assert_eq!(adapter.dispatch_count(), 0);
}

#[test]
fn dispatch_request_rejects_unbound_render_evidence_before_adapter_effect() {
    let adapter =
        ScriptedProvider::new([ProviderCapability::Streaming], successful_script()).unwrap();
    let prepared = adapter
        .prepare(&call(vec![ProviderCapability::Streaming]))
        .unwrap();
    let mut claim = ProviderDispatchClaim {
        call_id: prepared.call().call_id(),
        attempt_id: DispatchAttemptId::from_bytes([3; 16]),
        permit_id: [4; 16],
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [6; 32],
        token_reservation_id: [7; 16],
        cost_reservation_id: [8; 16],
        fencing_token: 1,
        provider_idempotency_key: "provider-render-binding".to_owned(),
    };
    claim.render_digest[0] ^= 1;

    assert_eq!(
        DispatchRequest::new(prepared, claim),
        Err(DispatchRequestError::PreparedClaimMismatch)
    );
    assert_eq!(adapter.dispatch_count(), 0);
}

#[test]
fn prepare_rejects_a_missing_required_capability_before_dispatch() {
    let adapter =
        ScriptedProvider::new([ProviderCapability::Streaming], successful_script()).unwrap();

    assert_eq!(
        adapter.prepare(&call(vec![ProviderCapability::Tools])),
        Err(PrepareError::UnsupportedCapability(
            ProviderCapability::Tools
        ))
    );
    assert_eq!(adapter.dispatch_count(), 0);
}

#[test]
fn replayed_attempt_returns_the_same_stream_without_second_dispatch() {
    let adapter =
        ScriptedProvider::new([ProviderCapability::Streaming], successful_script()).unwrap();
    let prepared = adapter
        .prepare(&call(vec![ProviderCapability::Streaming]))
        .unwrap();
    let request = dispatch_request(
        prepared,
        DispatchAttemptId::from_bytes([3; 16]),
        "provider-conformance-replay",
    );

    let first = block_on(adapter.dispatch(request.clone())).unwrap();
    let replay = block_on(adapter.dispatch(request)).unwrap();

    assert_eq!(first, replay);
    assert_eq!(adapter.dispatch_count(), 1);
}

#[test]
fn stream_is_ordered_and_conflicting_cursor_fails_closed() {
    let adapter =
        ScriptedProvider::new([ProviderCapability::Streaming], successful_script()).unwrap();
    let prepared = adapter
        .prepare(&call(vec![ProviderCapability::Streaming]))
        .unwrap();
    let stream = block_on(adapter.dispatch(dispatch_request(
        prepared,
        DispatchAttemptId::from_bytes([3; 16]),
        "provider-conformance-stream",
    )))
    .unwrap();

    let first = block_on(adapter.next(&stream, StreamCursor::new(0))).unwrap();
    assert_eq!(first.event().sequence(), 0);
    assert_eq!(
        block_on(adapter.next(&stream, StreamCursor::new(2))),
        Err(StreamError::SequenceGap {
            expected: 1,
            actual: 2,
        })
    );
}

#[test]
fn unknown_finish_reason_is_a_terminal_stream_error() {
    let script = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::RemoteFailed,
                reason: ProviderFinishReason::unknown("future-reason").unwrap(),
            },
        )
        .unwrap(),
    ];
    let adapter = ScriptedProvider::new([ProviderCapability::Streaming], script).unwrap();
    let prepared = adapter
        .prepare(&call(vec![ProviderCapability::Streaming]))
        .unwrap();
    let stream = block_on(adapter.dispatch(dispatch_request(
        prepared,
        DispatchAttemptId::from_bytes([3; 16]),
        "provider-conformance-unknown-reason",
    )))
    .unwrap();

    block_on(adapter.next(&stream, StreamCursor::new(0))).unwrap();
    assert!(matches!(
        block_on(adapter.next(&stream, StreamCursor::new(1))),
        Err(StreamError::UnknownFinishReason { .. })
    ));
}

#[test]
fn cancellation_is_idempotent_and_reconciliation_remains_explicit() {
    let adapter =
        ScriptedProvider::new([ProviderCapability::Streaming], successful_script()).unwrap();
    let prepared = adapter
        .prepare(&call(vec![ProviderCapability::Streaming]))
        .unwrap();
    let attempt_id = DispatchAttemptId::from_bytes([3; 16]);
    let stream = block_on(adapter.dispatch(dispatch_request(
        prepared,
        attempt_id,
        "provider-conformance-cancel",
    )))
    .unwrap();
    let cancel = CancelRequest::new(stream);

    assert_eq!(
        block_on(adapter.cancel(cancel.clone())).unwrap(),
        CancelDisposition::Requested
    );
    assert_eq!(
        block_on(adapter.cancel(cancel)).unwrap(),
        CancelDisposition::AlreadyRequested
    );
    assert_eq!(
        block_on(adapter.reconcile(ReconcileRequest::new(attempt_id))).unwrap(),
        ReconciliationDisposition::Uncertain
    );
}
