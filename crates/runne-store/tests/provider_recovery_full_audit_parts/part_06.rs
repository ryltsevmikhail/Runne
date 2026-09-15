#[test]
fn duplicate_settlement_replays_without_counter_change() {
    let (database, _claim, request) = terminal_setup("recovery-duplicate-settlement", 8);
    let execution = database.execution();
    assert_eq!(
        execution.commit_terminal(&request),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    let utilization_before = execution.utilization().unwrap();
    let before = database.query_connection();
    let snapshot_before = sql_snapshot(&before);
    let counts_before = (
        table_count(&before, "provider_budget_reservations"),
        table_count(&before, "provider_accounting_settlements"),
        table_count(&before, "provider_terminal_outbox"),
    );
    drop(before);

    assert_eq!(
        execution.commit_terminal(&request),
        Ok(ProviderTerminalCommitOutcome::Replayed)
    );
    assert_eq!(execution.utilization().unwrap(), utilization_before);
    let after = database.query_connection();
    assert_eq!(sql_snapshot(&after), snapshot_before);
    assert_eq!(
        (
            table_count(&after, "provider_budget_reservations"),
            table_count(&after, "provider_accounting_settlements"),
            table_count(&after, "provider_terminal_outbox"),
        ),
        counts_before
    );
    assert_eq!(
        execution.utilization().unwrap().0.remaining,
        utilization_before.0.remaining
    );
    assert_eq!(
        execution.utilization().unwrap().1.remaining,
        utilization_before.1.remaining
    );
}

#[test]
fn subscription_zero_xxx_settles_without_fake_money_charge() {
    let (database, _claim, request) = zero_cost_terminal_setup("recovery-zero-xxx", 81);
    let execution = database.execution();
    assert_eq!(
        execution.commit_terminal(&request),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    let connection = database.query_connection();
    let settlement: (i64, String) = connection
        .query_row(
            "SELECT charge_micros, currency FROM provider_accounting_settlements",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(settlement, (0, "XXX".to_owned()));
    let reservations: Vec<(i64, i64, Option<i64>)> = connection
        .prepare(
            "SELECT dimension, amount, settled_amount
             FROM provider_budget_reservations ORDER BY dimension",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(reservations[1], (2, 0, Some(0)));
}
