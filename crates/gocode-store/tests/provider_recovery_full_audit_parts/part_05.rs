#[test]
fn duplicate_acknowledgement_exact_receipt_replays_and_conflict_fails_closed() {
    let (database, claim, request) = terminal_setup("recovery-duplicate-ack", 7);
    let execution = database.execution();
    execution.commit_terminal(&request).unwrap();
    let pending = execution.pending_terminal_outbox().unwrap();
    assert_eq!(pending.len(), 1);
    let outbox_id = pending[0].outbox_id;
    let receipt = [71; 32];

    execution.acknowledge_terminal_outbox(outbox_id, receipt).unwrap();
    assert_eq!(
        database
            .dispatch()
            .get_dispatch(claim.attempt_id)
            .unwrap()
            .unwrap()
            .state,
        ProviderDispatchState::Settled
    );
    let before_replay = database.query_connection();
    let before_replay = sql_snapshot(&before_replay);
    execution.acknowledge_terminal_outbox(outbox_id, receipt).unwrap();
    let after_replay = database.query_connection();
    assert_eq!(sql_snapshot(&after_replay), before_replay);
    assert_eq!(
        database
            .dispatch()
            .get_dispatch(claim.attempt_id)
            .unwrap()
            .unwrap()
            .state,
        ProviderDispatchState::Settled
    );

    assert_eq!(
        execution.acknowledge_terminal_outbox(outbox_id, [72; 32]),
        Err(ProviderExecutionError::OutboxConflict)
    );
    assert_eq!(
        execution.acknowledge_terminal_outbox(outbox_id, [0; 32]),
        Err(ProviderExecutionError::OutboxConflict)
    );
    let after_conflicts = database.query_connection();
    assert_eq!(sql_snapshot(&after_conflicts), before_replay);
}
