use futures::executor::block_on;
use gocode_provider::{
    CancelDisposition, CancelRequest, DispatchAttemptId, DispatchRequest, ModelRef, PrepareError,
    ProviderCall, ProviderCallId, ProviderCapability, ProviderFinishReason, ProviderId,
    ProviderPort, ProviderStreamEvent, ProviderStreamEventKind, ReconcileRequest,
    ReconciliationDisposition, ScriptedProvider, StreamCursor, StreamError,
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
                reason: ProviderFinishReason::Stop,
            },
        )
        .unwrap(),
    ]
}

#[test]
fn prepare_is_deterministic_and_has_no_dispatch_effect() {
    let adapter =
        ScriptedProvider::new([ProviderCapability::Streaming], successful_script()).unwrap();
    let provider_call = call(vec![ProviderCapability::Streaming]);

    let left = adapter.prepare(&provider_call).unwrap();
    let right = adapter.prepare(&provider_call).unwrap();

    assert_eq!(left, right);
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
    let request = DispatchRequest::new(prepared, DispatchAttemptId::from_bytes([3; 16]));

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
    let stream = block_on(adapter.dispatch(DispatchRequest::new(
        prepared,
        DispatchAttemptId::from_bytes([3; 16]),
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
                reason: ProviderFinishReason::unknown("future-reason").unwrap(),
            },
        )
        .unwrap(),
    ];
    let adapter = ScriptedProvider::new([ProviderCapability::Streaming], script).unwrap();
    let prepared = adapter
        .prepare(&call(vec![ProviderCapability::Streaming]))
        .unwrap();
    let stream = block_on(adapter.dispatch(DispatchRequest::new(
        prepared,
        DispatchAttemptId::from_bytes([3; 16]),
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
    let stream = block_on(adapter.dispatch(DispatchRequest::new(prepared, attempt_id))).unwrap();
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
