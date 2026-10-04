#[test]
fn restart_with_pending_settlement_preserves_reserved_settled_remaining() {
    let (database, claim, terminal) = terminal_setup("recovery-pending-settlement-restart", 18);
    let execution = database.execution();
    assert_eq!(
        execution.commit_terminal(&terminal),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    assert_eq!(dispatch_state(&database, &claim), ProviderDispatchState::TerminalPendingCommit);
    assert_eq!(execution.pending_terminal_outbox().unwrap().len(), 1);
    let before = database.query_connection();
    let snapshot_before = sql_snapshot(&before);
    let reservations_before = sql_table_rows(&before, "provider_budget_reservations");
    let accounting_before = sql_table_rows(&before, "provider_accounting_settlements");
    let outbox_before = sql_table_rows(&before, "provider_terminal_outbox");
    let dispatch_before = sql_table_rows(&before, "provider_dispatch_attempts");
    let authority_before = sql_table_rows(&before, "provider_runtime_authority_state");
    let utilization_before = execution.utilization().unwrap();
    assert_remaining(utilization_before);
    assert_eq!(active_reservation_count(&before), 0);
    let mut reservation_statement = before
        .prepare(
            "SELECT dimension, amount, state, settled_amount, released_at
             FROM provider_budget_reservations
             WHERE provider_idempotency_key = ?1 ORDER BY dimension",
        )
        .unwrap();
    let reservations = reservation_statement
        .query_map([claim.provider_idempotency_key.as_str()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    drop(reservation_statement);
    let admitted = before
        .query_row(
            "SELECT requested_input_tokens, requested_output_tokens, max_cost_micros
             FROM provider_execution_admissions WHERE dispatch_attempt_id = ?1",
            [claim.attempt_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
        )
        .unwrap();
    let usage = terminal.usage();
    assert_eq!(reservations.len(), 2);
    assert_eq!(reservations[0].0, 1);
    assert_eq!(reservations[0].1, admitted.0 + admitted.1);
    assert_eq!(reservations[0].2, 2);
    assert_eq!(
        reservations[0].3,
        Some(i64::try_from(usage.total_tokens()).unwrap())
    );
    assert!(reservations[0].4.is_some());
    assert_eq!(reservations[1].0, 2);
    assert_eq!(reservations[1].1, admitted.2);
    assert_eq!(reservations[1].2, 2);
    assert_eq!(
        reservations[1].3,
        Some(i64::try_from(terminal.charge_micros()).unwrap())
    );
    assert!(reservations[1].4.is_some());
    assert_eq!(
        before
            .query_row(
                "SELECT settlement_digest, input_tokens, output_tokens, cached_input_tokens,
                        reasoning_output_tokens, charge_micros, currency
                 FROM provider_accounting_settlements WHERE dispatch_attempt_id = ?1",
                [claim.attempt_id.as_bytes().as_slice()],
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
        (
            terminal.settlement_digest().to_vec(),
            i64::try_from(usage.input_tokens()).unwrap(),
            i64::try_from(usage.output_tokens()).unwrap(),
            i64::try_from(usage.cached_input_tokens()).unwrap(),
            i64::try_from(usage.reasoning_output_tokens()).unwrap(),
            i64::try_from(terminal.charge_micros()).unwrap(),
            terminal.currency().to_owned(),
        )
    );
    assert_eq!(
        before.query_row(
            "SELECT COUNT(*) FROM provider_terminal_outbox WHERE state = 1",
            [],
            |row| row.get::<_, i64>(0),
        ).unwrap(),
        1
    );
    drop(before);
    drop(execution);

    let reopened_execution = database.execution();
    let reopened_dispatch = database.dispatch();
    assert_eq!(
        reopened_dispatch.get_dispatch(claim.attempt_id).unwrap().unwrap().state,
        ProviderDispatchState::TerminalPendingCommit
    );
    assert_eq!(reopened_execution.pending_terminal_outbox().unwrap().len(), 1);
    assert_eq!(reopened_execution.utilization().unwrap(), utilization_before);
    assert_remaining(reopened_execution.utilization().unwrap());
    let after = database.query_connection();
    assert_eq!(sql_snapshot(&after), snapshot_before);
    assert_eq!(sql_table_rows(&after, "provider_budget_reservations"), reservations_before);
    assert_eq!(sql_table_rows(&after, "provider_accounting_settlements"), accounting_before);
    assert_eq!(sql_table_rows(&after, "provider_terminal_outbox"), outbox_before);
    assert_eq!(sql_table_rows(&after, "provider_dispatch_attempts"), dispatch_before);
    assert_eq!(sql_table_rows(&after, "provider_runtime_authority_state"), authority_before);
    assert_eq!(active_reservation_count(&after), 0);
    assert_eq!(
        after.query_row(
            "SELECT COUNT(*) FROM provider_terminal_outbox WHERE state = 1",
            [],
            |row| row.get::<_, i64>(0),
        ).unwrap(),
        1
    );
}

#[test]
fn v50_completed_terminal_reopens_before_and_after_outbox_acknowledgement() {
    let (database, claim, terminal) = terminal_setup("v50-disposition-mapping", 19);
    let execution = database.execution();
    assert_eq!(
        execution.commit_terminal(&terminal),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    let outbox_id = execution.pending_terminal_outbox().unwrap()[0].outbox_id;

    let connection = database.query_connection();
    let populated: (i64, i64, i64, i64, i64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_dispatch_attempts WHERE attempt_id=?1),
                    (SELECT COUNT(*) FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1),
                    (SELECT COUNT(*) FROM provider_terminal_dispositions WHERE dispatch_attempt_id=?1),
                    a.state, d.disposition, a.settlement_digest, s.settlement_digest
             FROM provider_dispatch_attempts a
             JOIN provider_accounting_settlements s ON s.dispatch_attempt_id=a.attempt_id
             JOIN provider_terminal_dispositions d ON d.dispatch_attempt_id=a.attempt_id
             WHERE a.attempt_id=?1",
            [claim.attempt_id.as_bytes().as_slice()],
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
        .unwrap();
    assert_eq!((populated.0, populated.1, populated.2), (1, 1, 1));
    assert_eq!((populated.3, populated.4), (4, 1));
    assert_eq!(
        populated.5.as_slice(),
        terminal.settlement_digest().as_slice()
    );
    assert_eq!(populated.5, populated.6);
    drop(connection);
    assert!(
        validated_reopen::open_provider_execution(database.path(), database.identity()).is_ok()
    );

    for disposition in [2, 3, 4] {
        set_v50_terminal_pair(&database, claim.attempt_id.as_bytes(), 4, disposition);
        assert!(
            validated_reopen::open_provider_execution(database.path(), database.identity())
                .is_err(),
            "non-completed disposition {disposition} cannot reopen with completed state 4"
        );
        set_v50_terminal_pair(&database, claim.attempt_id.as_bytes(), 4, 1);
        assert!(
            validated_reopen::open_provider_execution(database.path(), database.identity())
                .is_ok()
        );
    }

    let receipt_digest = [0x45; 32];
    execution
        .acknowledge_terminal_outbox(outbox_id, receipt_digest)
        .unwrap();
    drop(execution);
    let acknowledged = database.query_connection();
    let persisted: (i64, i64, Vec<u8>) = acknowledged
        .query_row(
            "SELECT a.state, o.state, o.receipt_digest
             FROM provider_dispatch_attempts a
             JOIN provider_terminal_outbox o ON o.dispatch_attempt_id=a.attempt_id
             WHERE a.attempt_id=?1",
            [claim.attempt_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((persisted.0, persisted.1), (5, 2));
    assert_eq!(persisted.2, receipt_digest);
    drop(acknowledged);
    assert!(
        validated_reopen::open_provider_execution(database.path(), database.identity()).is_ok()
    );

    // ACK replay is idempotent and the acknowledged lifecycle remains valid.
    let replay = database.execution();
    replay
        .acknowledge_terminal_outbox(outbox_id, receipt_digest)
        .unwrap();
    drop(replay);
    assert!(
        validated_reopen::open_provider_execution(database.path(), database.identity()).is_ok()
    );
}

fn set_v50_terminal_pair(
    database: &ArmedProviderTestDatabase,
    dispatch_attempt_id: &[u8; 16],
    state: i64,
    disposition: i64,
) {
    let connection = Connection::open(database.path()).unwrap();
    connection
        .execute_batch("DROP TRIGGER provider_terminal_dispositions_immutable;")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_dispatch_attempts SET state=?1 WHERE attempt_id=?2",
            params![state, dispatch_attempt_id.as_slice()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE provider_terminal_dispositions SET disposition=?1 WHERE dispatch_attempt_id=?2",
            params![disposition, dispatch_attempt_id.as_slice()],
        )
        .unwrap();
    connection
        .execute_batch("CREATE TRIGGER provider_terminal_dispositions_immutable BEFORE UPDATE ON provider_terminal_dispositions BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END;")
        .unwrap();
    let populated: (i64, i64, i64, i64, i64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_dispatch_attempts WHERE attempt_id=?1),
                    (SELECT COUNT(*) FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1),
                    (SELECT COUNT(*) FROM provider_terminal_dispositions WHERE dispatch_attempt_id=?1),
                    a.state, d.disposition, a.settlement_digest, s.settlement_digest
             FROM provider_dispatch_attempts a
             JOIN provider_accounting_settlements s ON s.dispatch_attempt_id=a.attempt_id
             JOIN provider_terminal_dispositions d ON d.dispatch_attempt_id=a.attempt_id
             WHERE a.attempt_id=?1",
            [dispatch_attempt_id.as_slice()],
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
        .unwrap();
    assert_eq!((populated.0, populated.1, populated.2), (1, 1, 1));
    assert_eq!((populated.3, populated.4), (state, disposition));
    assert_eq!(populated.5, populated.6);
}
