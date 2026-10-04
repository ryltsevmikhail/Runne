fn conversation_writer_store(fixture: &Fixture) -> runne_store::store::StoreTransaction {
    runne_store::store::StoreTransaction::open_with_connections(
        fixture.path.to_str().unwrap(),
        validated_reopen::open_validated_connection(
            fixture.path.to_str().unwrap(),
            fixture.identity,
        )
        .unwrap(),
        validated_reopen::open_validated_reader(fixture.path.to_str().unwrap(), fixture.identity)
            .unwrap(),
        runne_application::ports::RuntimeAuthorityId(hex::encode([1; 16])),
        Arc::new(AllowingGuard),
    )
    .unwrap()
}

type UnknownOutputSnapshot = (
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
);

fn unknown_output_snapshot(fixture: &Fixture) -> UnknownOutputSnapshot {
    validated_connection(fixture)
        .query_row(
            "SELECT output_ciphertext,output_key_id,output_key_version,output_nonce,
                    output_digest,outbox_id,application_idempotency_key
             FROM provider_unknown_terminal_receipts WHERE dispatch_attempt_id=?1",
            [fixture.attempt_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn source1_unknown_stays_unpublished_after_alice_bob_alice_writer_heads() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let writer = runtime(&keyring, fixture.execution.as_ref());
    writer.preflight_existing_active_key([1; 16], 7).unwrap();
    let mut events = successful_events("source1-writer-head-replay");
    events[2] = ProviderStreamEvent::new(2, ProviderStreamEventKind::UsageUnavailable).unwrap();
    poll_events(&writer, &fixture, events).await;

    // The lawful fixture's original writer (Alice) began at token 1. Take
    // control through the same StoreTransaction API used by applications.
    let store = conversation_writer_store(&fixture);
    assert_eq!(
        store.take_control_conversation_writer_lease(
            fixture.conversation_id.as_bytes(),
            "principal-2",
            1,
        ),
        Ok(2)
    );
    assert_eq!(
        writer.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    let original_output = unknown_output_snapshot(&fixture);
    assert!(
        original_output.0.is_some(),
        "the factual output stays encrypted"
    );
    assert!(original_output.1.is_some(), "the output key stays pinned");
    assert_eq!(
        original_output.5, None,
        "Bob's current writer head denies publication"
    );
    assert!(original_output.3.is_some(), "the output nonce stays pinned");
    assert!(
        original_output.4.is_some(),
        "the output digest stays pinned"
    );
    assert_eq!(original_output.6, None);

    let connection = validated_connection(&fixture);
    for table in [
        "provider_terminal_outbox",
        "provider_accounting_settlements",
        "provider_remote_terminal_audit_receipts",
    ] {
        assert_eq!(
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0,
            "the Unknown decision under Bob's writer head must leave {table} empty"
        );
    }
    assert!(
        writer
            .recover_pending_terminal_outputs()
            .unwrap()
            .is_empty()
    );
    let tamper = rusqlite::Connection::open(&fixture.path).unwrap().execute(
        "UPDATE provider_unknown_terminal_receipts
             SET outbox_id=?1,application_idempotency_key='late-publication'
             WHERE dispatch_attempt_id=?2",
        rusqlite::params![
            [0xB2_u8; 16].as_slice(),
            fixture.attempt_id.as_bytes().as_slice()
        ],
    );
    assert!(
        tamper.is_err(),
        "append-only receipt protects nullable publication fields"
    );
    assert_eq!(unknown_output_snapshot(&fixture), original_output);
    let reserves = connection
        .prepare("SELECT state,settled_amount,released_at FROM provider_budget_reservations ORDER BY dimension")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, Option<i64>>(2)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(reserves, vec![(1, None, None), (1, None, None)]);

    assert_eq!(
        store.take_control_conversation_writer_lease(
            fixture.conversation_id.as_bytes(),
            "principal-1",
            2,
        ),
        Ok(3)
    );
    assert_eq!(
        writer.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Replayed)
    );
    assert_eq!(unknown_output_snapshot(&fixture), original_output);
    assert_eq!(
        validated_connection(&fixture)
            .query_row(
                "SELECT owner_principal,fencing_token FROM conversation_writer_leases WHERE conversation_id=?1",
                [fixture.conversation_id.as_bytes().as_slice()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap(),
        ("principal-1".to_owned(), 3)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn source1_concurrent_fresh_unknown_commits_once_and_replays_once() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let writer = runtime(&keyring, fixture.execution.as_ref());
    writer.preflight_existing_active_key([1; 16], 7).unwrap();
    let mut events = successful_events("source1-concurrent-unknown");
    events[2] = ProviderStreamEvent::new(2, ProviderStreamEventKind::UsageUnavailable).unwrap();
    poll_events(&writer, &fixture, events).await;
    let context = context(&fixture);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let (first, second) = std::thread::scope(|scope| {
        let first_barrier = Arc::clone(&barrier);
        let first_keyring = Arc::clone(&keyring);
        let first_execution = Arc::clone(&fixture.execution);
        let first_context = context;
        let first = scope.spawn(move || {
            let runtime = runtime(&first_keyring, first_execution.as_ref());
            first_barrier.wait();
            runtime.finalize_terminal_output(&first_context)
        });
        let second_barrier = Arc::clone(&barrier);
        let second_keyring = Arc::clone(&keyring);
        let second_execution = Arc::clone(&fixture.execution);
        let second_context = context;
        let second = scope.spawn(move || {
            let runtime = runtime(&second_keyring, second_execution.as_ref());
            second_barrier.wait();
            runtime.finalize_terminal_output(&second_context)
        });
        barrier.wait();
        (first.join().unwrap(), second.join().unwrap())
    });
    let outcomes = [first, second];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Ok(ProviderTerminalCommitOutcome::Committed))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Ok(ProviderTerminalCommitOutcome::Replayed))
            .count(),
        1
    );
    assert_eq!(
        validated_connection(&fixture)
            .query_row(
                "SELECT COUNT(*) FROM provider_unknown_terminal_receipts WHERE dispatch_attempt_id=?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}
