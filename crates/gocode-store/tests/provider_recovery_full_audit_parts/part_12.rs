fn assert_remaining(utilization: (gocode_application::provider::ProviderBudgetUtilization, gocode_application::provider::ProviderBudgetUtilization)) {
    assert_eq!(
        utilization.0.remaining,
        utilization.0.limit - utilization.0.reserved - utilization.0.settled
    );
    assert_eq!(
        utilization.1.remaining,
        utilization.1.limit - utilization.1.reserved - utilization.1.settled
    );
}

#[test]
fn uncertain_reservation_survives_restart_with_exact_counters() {
    let (database, request, _record) = setup("recovery-uncertain-restart", 17);
    let claim = issue_winner(&database, &request);
    let dispatch = database.dispatch();
    assert_eq!(
        dispatch.mark_uncertain(claim.attempt_id, claim.fencing_token),
        Ok(ProviderDispatchState::Uncertain)
    );
    let execution = database.execution();
    let before = database.query_connection();
    let snapshot_before = sql_snapshot(&before);
    let reservations_before = sql_table_rows(&before, "provider_budget_reservations");
    let authority_before = sql_table_rows(&before, "provider_runtime_authority_state");
    let utilization_before = execution.utilization().unwrap();
    assert_remaining(utilization_before);
    assert_eq!(active_reservation_count(&before), 2);
    assert_eq!(table_count(&before, "provider_accounting_settlements"), 0);
    assert_eq!(table_count(&before, "provider_terminal_outbox"), 0);
    drop(before);
    drop(dispatch);
    drop(execution);

    let reopened_execution = database.execution();
    let reopened_dispatch = database.dispatch();
    assert_eq!(
        reopened_dispatch.get_dispatch(claim.attempt_id).unwrap().unwrap().state,
        ProviderDispatchState::Uncertain
    );
    assert_eq!(reopened_execution.utilization().unwrap(), utilization_before);
    assert_remaining(reopened_execution.utilization().unwrap());
    let after = database.query_connection();
    assert_eq!(sql_snapshot(&after), snapshot_before);
    assert_eq!(sql_table_rows(&after, "provider_budget_reservations"), reservations_before);
    assert_eq!(sql_table_rows(&after, "provider_runtime_authority_state"), authority_before);
    assert_eq!(active_reservation_count(&after), 2);
    assert_eq!(table_count(&after, "provider_accounting_settlements"), 0);
    assert_eq!(table_count(&after, "provider_terminal_outbox"), 0);
}
