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
