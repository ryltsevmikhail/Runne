const D2_TOOL_EVENT_LIMIT: u64 = 512;

fn poll_bound_events(count: usize) -> Vec<ProviderStreamEvent> {
    (0..count)
        .map(|sequence| {
            let kind = if sequence == 0 {
                ProviderStreamEventKind::Started
            } else {
                ProviderStreamEventKind::TextDelta { text: "x".into() }
            };
            ProviderStreamEvent::new(sequence as u64, kind).unwrap()
        })
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn text_next_and_commit_accepts_more_than_d2s_tool_event_limit() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    let events = poll_bound_events(D2_TOOL_EVENT_LIMIT as usize + 1);

    poll_events(&runtime, &fixture, events.clone()).await;

    assert_eq!(
        runtime.recover_events(fixture.attempt_id).unwrap(),
        events,
        "legacy text coordination must not inherit the D2 tool polling cap"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn d2_tool_collector_rejects_event_after_512_commits() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    let events = poll_bound_events(D2_TOOL_EVENT_LIMIT as usize + 1);
    let provider = CommitCheckingProvider {
        store: Arc::clone(&fixture.execution),
        attempt_id: fixture.attempt_id,
        events,
    };
    let stream_id = ProviderStreamId::from_bytes([9; 16]);
    let context = context(&fixture);
    let mut collector = runne_runtime::provider_tool::CommittedToolProposalCollector::new(
        0,
        String::new(),
        None,
        false,
        1024,
    )
    .unwrap();
    let mut cursor = 0;
    while cursor < D2_TOOL_EVENT_LIMIT {
        let (item, outcome) = runtime
            .next_and_commit_tool_aware(
                &provider,
                &stream_id,
                StreamCursor::new(cursor),
                &context,
                &mut collector,
            )
            .await
            .unwrap();
        assert_eq!(item.event().sequence(), cursor);
        assert!(outcome.is_none());
        cursor += 1;
    }

    assert_eq!(cursor, D2_TOOL_EVENT_LIMIT);
    let rejected = runtime
        .next_and_commit_tool_aware(
            &provider,
            &stream_id,
            StreamCursor::new(cursor),
            &context,
            &mut collector,
        )
        .await;
    assert_eq!(
        rejected.unwrap_err(),
        runne_runtime::provider_execution::RuntimeProviderExecutionError::TerminalRejected
    );
    assert_eq!(
        fixture
            .execution
            .load_encrypted_events(fixture.attempt_id)
            .unwrap()
            .len(),
        D2_TOOL_EVENT_LIMIT as usize + 1,
        "collector rejection follows the runtime's durable commit-before-accept path"
    );
}
