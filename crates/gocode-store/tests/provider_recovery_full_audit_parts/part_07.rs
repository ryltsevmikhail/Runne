#[test]
fn stale_lease_progress_operations_fail_before_mutation() {
    let (database, claim, terminal) = terminal_setup("recovery-stale-progress", 9);
    let stale = database.execution();
    database
        .execution()
        .install_runtime_authority_and_advance_worker_lease(&rotated_runtime_config())
        .unwrap();
    assert_eq!(dispatch_state(&database, &claim), ProviderDispatchState::Uncertain);
    let append = ProviderJournalAppendRequest {
        attempt_id: claim.attempt_id,
        fencing_token: claim.fencing_token,
        sequence: 1,
        event_kind: 2,
        terminal: false,
        call_digest_version: ProviderCallDigestVersion::V2,
        profile_digest: [2; 32],
        runtime_generation: 11,
        key: terminal.key(),
        encrypted: encrypted_payload(121, 122),
    };

    let before_append = database.query_connection();
    let before_append = sql_snapshot(&before_append);
    assert_eq!(
        stale.append_encrypted_event(&append),
        Err(ProviderExecutionError::StaleGeneration)
    );
    let after_append = database.query_connection();
    assert_eq!(sql_snapshot(&after_append), before_append);

    let before_terminal = database.query_connection();
    let before_terminal = sql_snapshot(&before_terminal);
    assert_eq!(
        stale.commit_terminal(&terminal),
        Err(ProviderExecutionError::StaleGeneration)
    );
    let after_terminal = database.query_connection();
    assert_eq!(sql_snapshot(&after_terminal), before_terminal);

    let before_uncertain = database.query_connection();
    let before_uncertain = sql_snapshot(&before_uncertain);
    assert_eq!(
        stale.mark_execution_uncertain(claim.attempt_id, claim.fencing_token),
        Err(ProviderExecutionError::StaleGeneration)
    );
    let after_uncertain = database.query_connection();
    assert_eq!(sql_snapshot(&after_uncertain), before_uncertain);
}
