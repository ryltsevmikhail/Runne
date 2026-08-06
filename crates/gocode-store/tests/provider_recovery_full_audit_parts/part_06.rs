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
    assert_eq!(execution.utilization().unwrap().0.remaining, utilization_before.0.remaining);
    assert_eq!(execution.utilization().unwrap().1.remaining, utilization_before.1.remaining);
}
