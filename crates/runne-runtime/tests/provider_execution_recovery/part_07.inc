#[tokio::test(flavor = "current_thread")]
async fn validated_reopen_after_outbox_ack_does_not_reapply_terminal_output() {
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let writer = runtime(&keyring, fixture.execution.as_ref());
    writer.create_and_activate_key([1; 16], 7, 1).unwrap();
    poll_events(
        &writer,
        &fixture,
        successful_events("durable-terminal-receipt-read"),
    )
    .await;
    writer.finalize_terminal_output(&context(&fixture)).unwrap();
    let application = IdempotentTerminalApplication::default();
    assert_eq!(
        writer.apply_terminal_output_for_attempt(fixture.attempt_id, &application),
        Ok(true)
    );
    assert_eq!(application.calls.load(Ordering::SeqCst), 1);
    let before = validated_connection(&fixture);
    let snapshot_before = sql_snapshot(&before);
    assert_eq!(
        before
            .query_row(
                "SELECT state, receipt_digest FROM provider_terminal_outbox",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .unwrap(),
        (2, Some(vec![77; 32]))
    );
    assert_eq!(
        before
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        5
    );
    drop(before);

    let reopened_store = validated_reopen::open_provider_execution(
        fixture.path.to_str().unwrap(),
        fixture.identity,
    )
    .unwrap();
    let reopened = runtime(&keyring, &reopened_store);
    assert!(reopened.recover_pending_terminal_outputs().unwrap().is_empty());
    assert_eq!(
        reopened.apply_terminal_output_for_attempt(fixture.attempt_id, &application),
        Ok(false)
    );
    assert_eq!(application.calls.load(Ordering::SeqCst), 1);
    assert_eq!(sql_snapshot(&validated_connection(&fixture)), snapshot_before);
}

#[tokio::test(flavor = "current_thread")]
async fn stale_generation_finalize_is_recovery_frozen() {
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    poll_events(
        &runtime,
        &fixture,
        successful_events("stale-generation-terminal-evidence"),
    )
    .await;
    let stale_context = context(&fixture);
    fixture
        .execution
        .install_runtime_authority_and_advance_worker_lease(&rotated_runtime_authority_config())
        .unwrap();
    let before = validated_connection(&fixture);
    let snapshot_before = sql_snapshot(&before);
    assert_eq!(
        before
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        6
    );
    drop(before);

    assert_eq!(
        runtime.finalize_terminal_output(&stale_context),
        Err(RuntimeProviderExecutionError::RecoveryFrozen)
    );
    assert_eq!(sql_snapshot(&validated_connection(&fixture)), snapshot_before);
}
