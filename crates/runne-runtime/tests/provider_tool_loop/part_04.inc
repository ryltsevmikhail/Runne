
#[tokio::test]
async fn runtime_rejects_adapter_event_that_bypasses_stream_grammar() {
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
    let loop_ = test_loop(
        Journal::default(),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(
                &provider,
                ProviderStreamId::from_bytes([3; 16]),
                &CancellationToken::new(),
            )
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
}

struct BlockingRedaction;

impl runne_runtime::provider_redaction::ProviderEventRedaction for BlockingRedaction {
    fn scan_before_journal(
        &self,
        _context: &runne_runtime::provider_execution::ProviderEventJournalContext,
        event: &ProviderStreamEvent,
    ) -> Result<
        runne_runtime::provider_redaction::PreJournalProviderEvent,
        runne_runtime::provider_redaction::ProviderRedactionError,
    > {
        use runne_runtime::provider_redaction::PreJournalProviderEvent;
        if matches!(event.kind(), ProviderStreamEventKind::TextDelta { .. }) {
            return Ok(PreJournalProviderEvent::Terminal(
                runne_provider::ScannerTerminalDisposition::Uncertain(
                    runne_provider::ScannerUncertainReason::SecretDetected,
                ),
            ));
        }
        Ok(PreJournalProviderEvent::Append(event.clone()))
    }

    fn terminal_disposition(
        &self,
        _attempt: DispatchAttemptId,
    ) -> Result<
        Option<runne_provider::ScannerTerminalDisposition>,
        runne_runtime::provider_redaction::ProviderRedactionError,
    > {
        Ok(Some(
            runne_provider::ScannerTerminalDisposition::Uncertain(
                runne_provider::ScannerUncertainReason::SecretDetected,
            ),
        ))
    }
}

#[tokio::test]
async fn provider_tool_journal_never_appends_boundary_rejected_text() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "credential-shaped-fixture".into(),
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let journal = Journal::default();
    let loop_ = ProviderToolLoop::new(
        journal.clone(),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
        &BlockingRedaction,
        runne_runtime::provider_execution::ProviderEventJournalContext {
            attempt_id: DispatchAttemptId::from_bytes([31; 16]),
            fencing_token: 3,
            call_digest_version: ProviderCallDigestVersion::V2,
            profile_digest: [4; 32],
            runtime_generation: 5,
        },
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
    assert_eq!(journal.events.lock().unwrap().len(), 1);
}
