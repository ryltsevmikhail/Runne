
async fn dispatch(provider: &ScriptedProvider) -> gocode_provider::ProviderStreamId {
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([1; 16]),
        ModelRef::new(ProviderId::new("fake").unwrap(), "model", "revision").unwrap(),
        [2; 32],
        100,
        serde_json::json!({}),
    )
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    let prepared = provider.prepare(&call).unwrap();
    let claim = ProviderDispatchClaim {
        call_id: prepared.call().call_id(),
        attempt_id: DispatchAttemptId::from_bytes([3; 16]),
        permit_id: [4; 16],
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [6; 32],
        token_reservation_id: [7; 16],
        cost_reservation_id: [8; 16],
        fencing_token: 1,
        provider_idempotency_key: "runtime-provider-tool-loop".to_owned(),
    };
    provider
        .dispatch(DispatchRequest::new(prepared, claim).unwrap())
        .await
        .unwrap()
}

fn handoff(disposition: ToolHandoffDisposition) -> ToolHandoff {
    ToolHandoff {
        disposition,
        calls: Mutex::new(Vec::new()),
    }
}

struct BypassProvider {
    item: ProviderStreamItem,
}

impl ProviderPort for BypassProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        digest_version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, digest_version)
    }

    fn dispatch(
        &self,
        _request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!("runtime boundary test supplies a stream") })
    }

    fn next<'a>(
        &'a self,
        _stream: &'a ProviderStreamId,
        _cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        let item = self.item.clone();
        Box::pin(async move { Ok(item) })
    }

    fn cancel(
        &self,
        _request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { Ok(CancelDisposition::Requested) })
    }

    fn reconcile(
        &self,
        _request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }
}

#[tokio::test]
async fn text_completion_persists_every_event_before_success() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "hello".into(),
            },
        ),
        event(
            2,
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(2, 1, 0, 0).unwrap(),
            },
        ),
        event(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let loop_ = ProviderToolLoop::new(
        Journal::default(),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Completed {
            text: "hello".into(),
            usage: Some(ProviderUsage::new(2, 1, 0, 0).unwrap()),
        }
    );
}

#[tokio::test]
async fn tool_request_is_persisted_before_handoff_and_result_before_continuation() {
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
    let loop_ = ProviderToolLoop::new(
        Journal::default(),
        handoff(ToolHandoffDisposition::Completed {
            result_digest: [9; 32],
        }),
        64,
    )
    .unwrap();
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::ToolResultReady {
            call_id: "call-1".into(),
            result_digest: [9; 32]
        }
    );
}

#[tokio::test]
async fn cancellation_intent_precedes_adapter_signal() {
    let provider = provider(vec![event(0, ProviderStreamEventKind::Started)]);
    let stream = dispatch(&provider).await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let loop_ = ProviderToolLoop::new(
        Journal::default(),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();
    assert_eq!(
        loop_.run(&provider, stream, &cancellation).await.unwrap(),
        ProviderToolLoopOutcome::Cancelled
    );
}

#[tokio::test]
async fn malformed_or_uncertain_effect_freezes_the_loop() {
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
    let loop_ = ProviderToolLoop::new(
        Journal::default(),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
}

#[tokio::test]
async fn restart_uses_durable_cursor_and_does_not_replay_started() {
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
    provider.next(&stream, StreamCursor::new(0)).await.unwrap();
    let loop_ = ProviderToolLoop::new(
        Journal {
            cursor: 1,
            ..Journal::default()
        },
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();
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
async fn restart_restores_usage_and_rejects_a_second_usage_event() {
    let provider = BypassProvider {
        item: ProviderStreamItem::from_event(event(
            2,
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(3, 1, 0, 0).unwrap(),
            },
        ))
        .unwrap(),
    };
    let loop_ = ProviderToolLoop::new(
        Journal {
            cursor: 2,
            usage: Some(ProviderUsage::new(2, 1, 0, 0).unwrap()),
            ..Journal::default()
        },
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
