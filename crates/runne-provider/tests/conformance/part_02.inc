
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
                text: "x".repeat(runne_provider::MAX_PROVIDER_TEXT_DELTA_BYTES + 1),
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
                "text": "x".repeat(runne_provider::MAX_PROVIDER_TEXT_DELTA_BYTES + 1)
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
        provider_id: prepared.call().model_ref().provider_id().clone(),
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
