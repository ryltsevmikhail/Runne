
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
    let loop_ = ProviderToolLoop::new(
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
