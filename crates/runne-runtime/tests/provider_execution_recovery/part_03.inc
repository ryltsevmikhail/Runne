
#[tokio::test(flavor = "current_thread")]
async fn remote_failure_without_usage_consumes_full_reservation_without_conversation_outbox() {
    const PARTIAL: &str = "remote-failed-partial-must-not-be-applied-83";
    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &RESERVATION_PRICING,
        &DENYING_GUARD,
        &ALLOWING_REDACTION,
    );
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: PARTIAL.to_owned(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(2, ProviderStreamEventKind::UsageUnavailable).unwrap(),
        ProviderStreamEvent::new(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::RemoteFailed,
                reason: ProviderFinishReason::Error,
            },
        )
        .unwrap(),
    ];
    poll_events(&runtime, &fixture, events).await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Replayed)
    );
    assert!(
        runtime
            .recover_pending_terminal_outputs()
            .unwrap()
            .is_empty()
    );
    let connection = validated_connection(&fixture);
    assert_eq!(
        connection
            .query_row(
                "SELECT input_tokens, output_tokens, cached_input_tokens,
                        reasoning_output_tokens, charge_micros
                 FROM provider_accounting_settlements",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .unwrap(),
        (512, 1_024, 0, 0, 50_000)
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM provider_terminal_outbox", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_encryption_nonces WHERE purpose = 2",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        5
    );
    let reservations = connection
        .prepare(
            "SELECT dimension, settled_amount
             FROM provider_budget_reservations ORDER BY dimension",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(reservations, vec![(1, 1_536), (2, 50_000)]);
    let database = std::fs::read(&fixture.path).unwrap();
    assert!(
        !database
            .windows(PARTIAL.len())
            .any(|window| window == PARTIAL.as_bytes())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn prohibited_terminal_output_creates_no_accounting_or_outbox() {
    const OUTPUT: &str = "registered-prohibited-provider-output-marker-82";
    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &FIXED_PRICING,
        &DENYING_GUARD,
        &ALLOWING_REDACTION,
    );
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    poll_events(&runtime, &fixture, successful_events(OUTPUT)).await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Err(RuntimeProviderExecutionError::PolicyDenied)
    );
    let connection = validated_connection(&fixture);
    for table in [
        "provider_accounting_settlements",
        "provider_terminal_outbox",
    ] {
        assert_eq!(
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0,
            "policy denial mutated {table}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn mismatched_exact_profile_pricing_creates_no_accounting_or_outbox() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let openai_profile = OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .unwrap();
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &openai_profile,
        &ALLOWING_GUARD,
        &ALLOWING_REDACTION,
    );
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    poll_events(
        &runtime,
        &fixture,
        successful_events("exact-pricing-mismatch"),
    )
    .await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Err(RuntimeProviderExecutionError::PricingUnavailable)
    );
    let connection = validated_connection(&fixture);
    for table in [
        "provider_accounting_settlements",
        "provider_terminal_outbox",
    ] {
        assert_eq!(
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0,
            "pricing mismatch mutated {table}"
        );
    }
}

struct CommitCheckingProvider {
    store: Arc<SqliteProviderExecutionStore>,
    attempt_id: runne_provider::DispatchAttemptId,
    events: Vec<ProviderStreamEvent>,
}

impl ProviderPort for CommitCheckingProvider {
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
        Box::pin(async { unreachable!("fixture stream is already durable") })
    }

    fn next<'a>(
        &'a self,
        _stream: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        if cursor.sequence() > 0 {
            let committed = self
                .store
                .load_encrypted_events(self.attempt_id)
                .expect("previous event remains readable");
            assert_eq!(
                committed.len(),
                cursor.sequence() as usize,
                "runtime polled the next provider frame before prior journal commit"
            );
        }
        let event = self.events[cursor.sequence() as usize].clone();
        Box::pin(async move { ProviderStreamItem::from_event(event) })
    }

    fn cancel(
        &self,
        request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async move {
            assert_eq!(request.stream_id(), ProviderStreamId::from_bytes([9; 16]));
            Ok(CancelDisposition::Requested)
        })
    }

    fn reconcile(
        &self,
        _request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!("fixture does not reconcile") })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn each_event_commit_precedes_the_next_adapter_poll() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        )
        .unwrap(),
    ];
    let provider = CommitCheckingProvider {
        store: Arc::clone(&fixture.execution),
        attempt_id: fixture.attempt_id,
        events: events.clone(),
    };
    let stream_id = ProviderStreamId::from_bytes([9; 16]);

    for sequence in 0..2 {
        let item = runtime
            .next_and_commit(
                &provider,
                &stream_id,
                StreamCursor::new(sequence),
                &context(&fixture),
            )
            .await
            .unwrap();
        assert_eq!(item.event(), &events[sequence as usize]);
    }
}
