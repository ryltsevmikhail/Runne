fn assert_pending_terminal_settlement(
    connection: &rusqlite::Connection,
    fixture: &Fixture,
    settlement_digest: [u8; 32],
) {
    assert_eq!(
        connection
            .query_row(
                "SELECT settlement_digest, input_tokens, output_tokens, cached_input_tokens,
                        reasoning_output_tokens, charge_micros, currency
                 FROM provider_accounting_settlements WHERE dispatch_attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .unwrap(),
        (settlement_digest.to_vec(), 500, 900, 0, 0, 40_000, "USD".to_owned())
    );
    let mut statement = connection
        .prepare(
            "SELECT dimension, state, settled_amount, released_at
             FROM provider_budget_reservations ORDER BY dimension",
        )
        .unwrap();
    let reservations = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(reservations.len(), 2);
    assert_eq!(reservations[0].0, 1);
    assert_eq!(reservations[0].1, 2);
    assert_eq!(reservations[0].2, Some(1_400));
    assert!(reservations[0].3.is_some());
    assert_eq!(reservations[1].0, 2);
    assert_eq!(reservations[1].1, 2);
    assert_eq!(reservations[1].2, Some(40_000));
    assert!(reservations[1].3.is_some());
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
    assert_eq!(
        connection
            .query_row(
                "SELECT state, receipt_digest, settlement_digest FROM provider_terminal_outbox",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .unwrap(),
        (1, None, settlement_digest.to_vec())
    );
}

async fn assert_versioned_terminal_recovery(digest_version: ProviderCallDigestVersion) {
    let fixture = fixture_with_digest_version(digest_version);
    let keyring = fixture.keyring();
    let writer = runtime(&keyring, fixture.execution.as_ref());
    writer.preflight_existing_active_key([1; 16], 7).unwrap();
    let output = format!("versioned-terminal-output-{}", digest_version as u8);
    let events = successful_events(&output);
    poll_events(&writer, &fixture, events.clone()).await;
    assert_eq!(writer.recover_events(fixture.attempt_id).unwrap(), events);
    assert_eq!(
        writer.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    let pending = writer.recover_pending_terminal_outputs().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].output(), output.as_bytes());
    let settlement_digest = pending[0].record().settlement_digest;
    let before = validated_connection(&fixture);
    let expected_version = match digest_version {
        ProviderCallDigestVersion::V1 => 1_i64,
        ProviderCallDigestVersion::V2 => 2_i64,
    };
    for table in [
        "provider_prepared_requests",
        "provider_stream_journal",
        "provider_terminal_outbox",
    ] {
        assert_eq!(
            before
                .query_row(
                    &format!("SELECT call_digest_version FROM {table} LIMIT 1"),
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            expected_version,
            "{table} durable digest version"
        );
    }
    assert_pending_terminal_settlement(&before, &fixture, settlement_digest);
    let snapshot_before = sql_snapshot(&before);
    drop(before);

    let reopened_store = validated_reopen::open_provider_execution(
        fixture.path.to_str().unwrap(),
        fixture.identity,
    )
    .unwrap();
    let reopened = runtime(&keyring, &reopened_store);
    assert_eq!(reopened.recover_events(fixture.attempt_id).unwrap(), events);
    let pending = reopened.recover_pending_terminal_outputs().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].output(), output.as_bytes());
    let after = validated_connection(&fixture);
    assert_eq!(sql_snapshot(&after), snapshot_before);
    assert_pending_terminal_settlement(&after, &fixture, settlement_digest);
    drop(after);

    let application = IdempotentTerminalApplication::default();
    assert_eq!(
        reopened.apply_pending_terminal_outputs(&application, &IGNORING_RECOVERY_OBSERVER),
        Ok(1)
    );
    assert_eq!(application.calls.load(Ordering::SeqCst), 1);
    let applied = validated_connection(&fixture);
    assert_eq!(
        applied
            .query_row(
                "SELECT state, receipt_digest FROM provider_terminal_outbox",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .unwrap(),
        (2, Some(vec![77; 32]))
    );
    assert_eq!(
        applied
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        5
    );
    let snapshot_applied = sql_snapshot(&applied);
    drop(applied);
    assert_eq!(
        reopened.apply_pending_terminal_outputs(&application, &IGNORING_RECOVERY_OBSERVER),
        Ok(0)
    );
    assert_eq!(application.calls.load(Ordering::SeqCst), 1);
    assert_eq!(sql_snapshot(&validated_connection(&fixture)), snapshot_applied);
}

#[tokio::test(flavor = "current_thread")]
async fn v1_prepared_end_to_end_recovers_through_outbox_and_settlement() {
    assert_versioned_terminal_recovery(ProviderCallDigestVersion::V1).await;
}

#[tokio::test(flavor = "current_thread")]
async fn v2_prepared_end_to_end_recovers_through_outbox_and_settlement() {
    assert_versioned_terminal_recovery(ProviderCallDigestVersion::V2).await;
}

#[tokio::test(flavor = "current_thread")]
async fn call_digest_version_mismatch_fails_closed_without_mutation() {
    let fixture = fixture_with_digest_version(ProviderCallDigestVersion::V1);
    let keyring = fixture.keyring();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    poll_events(
        &runtime,
        &fixture,
        successful_events("mismatched-terminal-version"),
    )
    .await;
    let mismatched = ProviderEventJournalContext {
        call_digest_version: ProviderCallDigestVersion::V2,
        ..context(&fixture)
    };
    let before = validated_connection(&fixture);
    let snapshot_before = sql_snapshot(&before);
    drop(before);

    assert_eq!(
        runtime.finalize_terminal_output(&mismatched),
        Err(RuntimeProviderExecutionError::TerminalRejected)
    );
    let after = validated_connection(&fixture);
    assert_eq!(sql_snapshot(&after), snapshot_before);
}
