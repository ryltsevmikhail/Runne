#[tokio::test(flavor = "current_thread")]
async fn pending_outbox_is_not_decrypted_or_applied_without_scanner_completed() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let writer = runtime(&keyring, fixture.execution.as_ref());
    writer.preflight_existing_active_key([1; 16], 7).unwrap();
    poll_events(
        &writer,
        &fixture,
        successful_events("pending-output-must-remain-encrypted"),
    )
    .await;
    writer.finalize_terminal_output(&context(&fixture)).unwrap();

    let recovery = SqliteProviderRecoveryStore::open(&fixture.path, [1; 16]).unwrap();
    let binding = TailBinding::new(fixture.attempt_id, fixture.fencing_token, 1, 1, 1, 0).unwrap();
    recovery
        .commit_terminal(
            binding,
            ScannerTerminalDisposition::Uncertain(ScannerUncertainReason::SecretDetected),
        )
        .unwrap();
    let tails = ExecutionTailStore::default();
    let redaction = ProviderEventRedactionBoundary::new(&tails, &recovery, &ExecutionMatcher);
    let blocked = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &FIXED_PRICING,
        &ALLOWING_GUARD,
        &redaction,
    );
    let loads_before = keyring.loads.load(Ordering::SeqCst);

    assert!(matches!(
        blocked.recover_pending_terminal_outputs(),
        Err(RuntimeProviderExecutionError::PolicyDenied)
    ));
    assert_eq!(keyring.loads.load(Ordering::SeqCst), loads_before);
    let application = IdempotentTerminalApplication::default();
    assert_eq!(
        blocked.apply_terminal_output_for_attempt(fixture.attempt_id, &application),
        Err(RuntimeProviderExecutionError::PolicyDenied)
    );
    assert_eq!(application.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        validated_connection(&fixture)
            .query_row("SELECT state FROM provider_terminal_outbox", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
}

#[tokio::test(flavor = "current_thread")]
async fn every_provider_string_surface_is_scanned_before_journal() {
    let secret = std::str::from_utf8(EXECUTION_SECRET).unwrap();
    let cases = [
        ProviderStreamEventKind::ToolCallRequested {
            call_id: secret.into(),
            tool_name: "tool.run".into(),
            arguments_json: "{}".into(),
        },
        ProviderStreamEventKind::ToolCallRequested {
            call_id: "call-1".into(),
            tool_name: secret.into(),
            arguments_json: "{}".into(),
        },
        ProviderStreamEventKind::ToolCallRequested {
            call_id: "call-1".into(),
            tool_name: "tool.run".into(),
            arguments_json: format!(r#"{{"value":"{secret}"}}"#),
        },
        ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteFailed,
            reason: ProviderFinishReason::unknown(secret).unwrap(),
        },
    ];

    for kind in cases {
        let fixture = fixture();
        let recovery = SqliteProviderRecoveryStore::open(&fixture.path, [1; 16]).unwrap();
        let tails = ExecutionTailStore::default();
        let redaction = ProviderEventRedactionBoundary::new(&tails, &recovery, &ExecutionMatcher);
        let keyring = fixture.keyring();
        let runtime = RuntimeProviderExecution::new(
            keyring.as_ref(),
            fixture.execution.as_ref(),
            &FIXED_PRICING,
            &ALLOWING_GUARD,
            &redaction,
        );
        runtime.preflight_existing_active_key([1; 16], 7).unwrap();
        let provider = CommitCheckingProvider {
            store: Arc::clone(&fixture.execution),
            attempt_id: fixture.attempt_id,
            events: vec![
                ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
                ProviderStreamEvent::new(1, kind).unwrap(),
            ],
        };
        let stream = ProviderStreamId::from_bytes([9; 16]);
        runtime
            .next_and_commit(&provider, &stream, StreamCursor::new(0), &context(&fixture))
            .await
            .unwrap();

        assert_eq!(
            runtime
                .next_and_commit(&provider, &stream, StreamCursor::new(1), &context(&fixture))
                .await,
            Err(RuntimeProviderExecutionError::PolicyDenied)
        );
        assert_eq!(
            recovery
                .load(fixture.attempt_id)
                .unwrap()
                .unwrap()
                .disposition(),
            Some(ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::SecretDetected,
            ))
        );
        let recovered = runtime.recover_events(fixture.attempt_id).unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(matches!(
            recovered[0].kind(),
            ProviderStreamEventKind::Started
        ));
    }
}

#[test]
fn redaction_failure_observer_reports_only_fixed_site_and_kind() {
    #[derive(Default)]
    struct Observer(Mutex<Vec<(RedactionFailureSite, RedactionFailureKind)>>);
    impl ProviderRedactionObserver for Observer {
        fn observe_failure(&self, site: RedactionFailureSite, kind: RedactionFailureKind) {
            self.0.lock().unwrap().push((site, kind));
        }
    }

    let restart_fixture = fixture();
    let fixture = fixture();
    let recovery = SqliteProviderRecoveryStore::open(&fixture.path, [1; 16]).unwrap();
    let tails = ExecutionTailStore::default();
    tails.fail_put.store(true, Ordering::SeqCst);
    let observer = Observer::default();
    let boundary = ProviderEventRedactionBoundary::new(&tails, &recovery, &ExecutionMatcher)
        .with_observer(&observer);
    let event = ProviderStreamEvent::new(
        0,
        ProviderStreamEventKind::TextDelta {
            text: "fixture".into(),
        },
    )
    .unwrap();

    assert!(matches!(
        boundary.scan_before_journal(&context(&fixture), &event),
        Ok(PreJournalProviderEvent::Terminal(
            ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::CheckpointSecretStateUnavailable
            )
        ))
    ));
    assert_eq!(
        observer.0.lock().unwrap().as_slice(),
        &[(
            RedactionFailureSite::IngestTailPut,
            RedactionFailureKind::NativeUnavailable
        )]
    );

    let restart_recovery =
        SqliteProviderRecoveryStore::open(&restart_fixture.path, [1; 16]).unwrap();
    let restart_tails = ExecutionTailStore::default();
    let binding = TailBinding::new(
        restart_fixture.attempt_id,
        restart_fixture.fencing_token,
        1,
        1,
        1,
        0,
    )
    .unwrap();
    let mut session =
        runne_runtime::provider_redaction::ProviderRedactionRecovery::start(
            binding,
            &restart_tails,
            &restart_recovery,
            &ExecutionMatcher,
        )
        .unwrap();
    session.ingest(b"checkpoint", &mut Zeroizing::new(Vec::new())).unwrap();
    restart_tails.fail_load.store(true, Ordering::SeqCst);
    let restart_observer = Observer::default();
    runne_runtime::provider_redaction::ProviderRedactionRecovery::restart_with_observer(
        binding,
        &restart_tails,
        &restart_recovery,
        &ExecutionMatcher,
        Some(&restart_observer),
    )
    .unwrap();
    assert_eq!(
        restart_observer.0.lock().unwrap().as_slice(),
        &[(
            RedactionFailureSite::RestartTailLoad,
            RedactionFailureKind::NativeUnavailable
        )]
    );
}

#[test]
fn boundary_rejects_checkpoint_from_stale_context_authority() {
    let fixture = fixture();
    let recovery = SqliteProviderRecoveryStore::open(&fixture.path, [1; 16]).unwrap();
    let tails = ExecutionTailStore::default();
    let stale_binding =
        TailBinding::new(fixture.attempt_id, fixture.fencing_token + 1, 1, 1, 1, 0).unwrap();
    let mut staged = zeroize::Zeroizing::new(Vec::new());
    let mut stale = runne_runtime::provider_redaction::ProviderRedactionRecovery::start(
        stale_binding,
        &tails,
        &recovery,
        &ExecutionMatcher,
    )
    .unwrap();
    stale.ingest(b"clean checkpoint", &mut staged).unwrap();
    let boundary = ProviderEventRedactionBoundary::new(&tails, &recovery, &ExecutionMatcher);
    let event = ProviderStreamEvent::new(
        0,
        ProviderStreamEventKind::TextDelta {
            text: "new context bytes".into(),
        },
    )
    .unwrap();

    assert!(matches!(
        boundary.scan_before_journal(&context(&fixture), &event),
        Ok(PreJournalProviderEvent::Terminal(
            ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::CheckpointSecretStateUnavailable
            )
        ))
    ));
    assert_eq!(
        recovery
            .load(fixture.attempt_id)
            .unwrap()
            .unwrap()
            .disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CheckpointSecretStateUnavailable,
        ))
    );
}
