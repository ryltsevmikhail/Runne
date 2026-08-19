
#[tokio::test]
async fn crash_after_event_commit_recovers_exact_text_without_repolling_delta() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "durable".into(),
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
    let loop_ = test_loop(
        CrashAfterDurableDeltaJournal::default(),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Completed {
            text: "durable".into(),
            usage: None,
        }
    );
}

#[tokio::test]
async fn crash_after_terminal_event_commit_recovers_terminal_without_provider_repoll() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let loop_ = test_loop(
        CrashRecoveryJournal::new(CrashPoint::TerminalEvent),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Completed {
            text: String::new(),
            usage: None,
        }
    );
}

#[tokio::test]
async fn usage_unavailable_remote_terminal_survives_loop_crash_without_freeze_or_repoll() {
    const PARTIAL: &str = "remote-partial-recovery-marker";
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::TextDelta {
                text: PARTIAL.into(),
            },
        ),
        event(2, ProviderStreamEventKind::UsageUnavailable),
        event(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::RemoteFailed,
                reason: ProviderFinishReason::Error,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let loop_ = test_loop(
        CrashRecoveryJournal::new(CrashPoint::TerminalEvent),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    let recovered = loop_
        .run(&provider, stream, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        recovered,
        ProviderToolLoopOutcome::RemoteTerminal {
            disposition: ProviderTerminalDisposition::RemoteFailed,
            reason: ProviderFinishReason::Error,
            text: PARTIAL.into(),
            usage: None,
            usage_unavailable: true,
        }
    );
    assert!(!format!("{recovered:?}").contains(PARTIAL));
}

#[tokio::test]
async fn crash_after_tool_request_commit_freezes_without_tool_dispatch() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call-1".into(),
                tool_name: "process.exec".into(),
                arguments_json: "{}".into(),
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let loop_ = test_loop(
        CrashRecoveryJournal::new(CrashPoint::ToolEvent),
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
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
}

#[tokio::test]
async fn crash_after_tool_result_commit_recovers_result_without_second_tool_effect() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call-1".into(),
                tool_name: "process.exec".into(),
                arguments_json: "{}".into(),
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
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::ToolResultReady {
            call_id: "call-1".into(),
            result_digest: [9; 32],
        }
    );
}

#[tokio::test]
async fn crash_after_cancellation_intent_recovers_as_uncertain_without_repoll() {
    let provider = provider(vec![event(0, ProviderStreamEventKind::Started)]);
    let stream = dispatch(&provider).await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let loop_ = test_loop(
        CrashRecoveryJournal::new(CrashPoint::CancellationIntent),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_.run(&provider, stream, &cancellation).await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
}

#[tokio::test]
async fn crash_after_cancellation_ack_recovers_cancelled_without_second_signal() {
    let provider = provider(vec![event(0, ProviderStreamEventKind::Started)]);
    let stream = dispatch(&provider).await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let loop_ = test_loop(
        CrashRecoveryJournal::new(CrashPoint::CancellationAcknowledged),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_.run(&provider, stream, &cancellation).await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Cancelled
    );
}

#[tokio::test]
async fn crash_after_freeze_commit_recovers_fence_without_provider_repoll() {
    let provider = BypassProvider {
        item: ProviderStreamItem::from_event(event(
            100,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        ))
        .unwrap(),
    };
    let stream = ProviderStreamId::from_bytes([3; 16]);
    let loop_ = test_loop(
        CrashRecoveryJournal::new(CrashPoint::Frozen),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
}
