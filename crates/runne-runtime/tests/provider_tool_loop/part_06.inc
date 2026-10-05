#[tokio::test]
async fn complete_tool_response_is_persisted_before_proposal_is_returned() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call-1".into(),
                tool_name: "workspace.file.read".into(),
                arguments_json: "{\"path\":\"notes.txt\"}".into(),
            },
        ),
        event(2, ProviderStreamEventKind::UsageUnavailable),
        event(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::ToolCalls,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let journal = Journal::default();
    let tool_handoff = handoff(ToolHandoffDisposition::Uncertain);
    let loop_ = test_loop(journal.clone(), tool_handoff.clone(), 64).unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::ToolProposalReady {
            call: RuntimeToolCall {
                call_id: "call-1".into(),
                tool_name: "workspace.file.read".into(),
                arguments_json: "{\"path\":\"notes.txt\"}".into(),
            },
            text: String::new(),
            usage: None,
            usage_unavailable: true,
        }
    );
    assert!(tool_handoff.calls.lock().unwrap().is_empty());
    assert!(matches!(
        journal.recovery_state(stream).unwrap().status(),
        ProviderToolRecoveryStatus::ToolProposalReady { .. }
    ));
}

#[tokio::test]
async fn incomplete_tool_response_never_reaches_handoff_or_proposal_state() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call-1".into(),
                tool_name: "workspace.file.create_new".into(),
                arguments_json: "{\"path\":\"new.txt\"}".into(),
            },
        ),
        event(
            2,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let handoff = handoff(ToolHandoffDisposition::Completed {
        result_digest: [9; 32],
    });
    let loop_ = test_loop(Journal::default(), handoff.clone(), 64).unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
    assert!(handoff.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn crash_after_complete_proposal_commit_recovers_without_tool_dispatch() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call-1".into(),
                tool_name: "workspace.file.create_new".into(),
                arguments_json: "{\"path\":\"new.txt\"}".into(),
            },
        ),
        event(2, ProviderStreamEventKind::UsageUnavailable),
        event(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::ToolCalls,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let loop_ = test_loop(
        CrashRecoveryJournal::new(CrashPoint::ToolResult),
        handoff(ToolHandoffDisposition::Completed {
            result_digest: [9; 32],
        }),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert!(matches!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::ToolProposalReady { .. }
    ));
}

#[tokio::test]
async fn oversized_tool_arguments_freeze_without_proposal_or_handoff() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call-1".into(),
                tool_name: "workspace.file.read".into(),
                arguments_json: format!("{{\"path\":\"{}\"}}", "x".repeat(8192)),
            },
        ),
        event(2, ProviderStreamEventKind::UsageUnavailable),
        event(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::ToolCalls,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let handoff = handoff(ToolHandoffDisposition::Uncertain);
    let journal = Journal::default();
    let loop_ = test_loop(journal.clone(), handoff.clone(), 64).unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
    assert!(handoff.calls.lock().unwrap().is_empty());
    assert!(!matches!(
        journal.recovery_state(stream).unwrap().status(),
        ProviderToolRecoveryStatus::ToolProposalReady { .. }
    ));
}

#[tokio::test]
async fn multiple_tool_calls_freeze_without_handoff() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call-1".into(),
                tool_name: "workspace.file.read".into(),
                arguments_json: "{\"path\":\"a\"}".into(),
            },
        ),
        event(
            2,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call-2".into(),
                tool_name: "workspace.file.read".into(),
                arguments_json: "{\"path\":\"b\"}".into(),
            },
        ),
        event(3, ProviderStreamEventKind::UsageUnavailable),
        event(
            4,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::ToolCalls,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let handoff = handoff(ToolHandoffDisposition::Uncertain);
    let loop_ = test_loop(Journal::default(), handoff.clone(), 64).unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
    assert!(handoff.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn provider_event_budget_freezes_without_tool_effect() {
    let events = std::iter::once(event(0, ProviderStreamEventKind::Started))
        .chain((1..=512).map(|sequence| event(sequence, ProviderStreamEventKind::ScannerProgress)))
        .collect();
    let provider = provider(events);
    let stream = dispatch(&provider).await;
    let handoff = handoff(ToolHandoffDisposition::Uncertain);
    let loop_ = test_loop(Journal::default(), handoff.clone(), 64).unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
    assert!(handoff.calls.lock().unwrap().is_empty());
}
