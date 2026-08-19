#[test]
fn generation_rollback_and_same_generation_fence_replacement_fail_closed() {
    let (database, request, _record) = setup("recovery-rotation-rejections", 16);
    let _claim = issue_winner(&database, &request);
    let before = database.query_connection();
    let before = sql_snapshot(&before);

    let mut rollback = runtime_config();
    rollback.generation = 10;
    rollback.fencing_token = 12;
    assert_eq!(
        database
            .execution()
            .install_runtime_authority_and_advance_worker_lease(&rollback),
        Err(ProviderAdmissionError::StaleFencingToken)
    );
    let after_rollback = database.query_connection();
    assert_eq!(sql_snapshot(&after_rollback), before);

    let mut fence_replacement = runtime_config();
    fence_replacement.fencing_token = 14;
    assert_eq!(
        database
            .execution()
            .install_runtime_authority_and_advance_worker_lease(&fence_replacement),
        Err(ProviderAdmissionError::StaleFencingToken)
    );
    let after_replacement = database.query_connection();
    assert_eq!(sql_snapshot(&after_replacement), before);
}
