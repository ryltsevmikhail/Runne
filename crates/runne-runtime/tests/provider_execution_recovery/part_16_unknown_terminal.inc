#[tokio::test(flavor = "current_thread")]
async fn completed_without_usage_stays_factual_and_never_creates_known_settlement() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &FIXED_PRICING,
        &ALLOWING_GUARD,
        &ALLOWING_REDACTION,
    );
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    let mut events = successful_events("completed-without-usage");
    events[2] = ProviderStreamEvent::new(2, ProviderStreamEventKind::UsageUnavailable).unwrap();
    poll_events(&runtime, &fixture, events).await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(runne_application::provider::ProviderTerminalCommitOutcome::Committed)
    );
    let connection = validated_connection(&fixture);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_accounting_settlements",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM provider_unknown_terminal_receipts WHERE dispatch_attempt_id=?1 AND usage_present=0 AND accounting_reason=1 AND terminal_disposition=1",
            [fixture.attempt_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        ).unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_terminal_outbox WHERE dispatch_attempt_id=?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        4
    );
    let reserves = connection
        .prepare("SELECT settled_amount FROM provider_budget_reservations ORDER BY dimension")
        .unwrap()
        .query_map([], |row| row.get::<_, Option<i64>>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(reserves, vec![None, None]);
}

#[tokio::test(flavor = "current_thread")]
async fn existing_unknown_without_source_proof_never_falls_back_to_known_settlement() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let writer = runtime(&keyring, fixture.execution.as_ref());
    writer.preflight_existing_active_key([1; 16], 7).unwrap();
    let mut events = successful_events("unknown-proof-required-on-replay");
    events[2] = ProviderStreamEvent::new(2, ProviderStreamEventKind::UsageUnavailable).unwrap();
    poll_events(&writer, &fixture, events).await;
    assert_eq!(
        writer.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );

    let reopened =
        validated_reopen::open_provider_execution(fixture.path.to_str().unwrap(), fixture.identity)
            .unwrap();
    let replay = runtime(&keyring, &reopened);
    replay.preflight_existing_active_key([1; 16], 7).unwrap();
    assert_eq!(
        replay.finalize_terminal_output(&context(&fixture)),
        Err(RuntimeProviderExecutionError::TerminalRejected)
    );
    let connection = validated_connection(&fixture);
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM provider_unknown_terminal_receipts WHERE dispatch_attempt_id=?1",
            [fixture.attempt_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        ).unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}
