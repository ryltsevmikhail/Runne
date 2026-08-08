#[test]
fn unknown_call_digest_version_row_fails_closed_without_mutation() {
    let (database, _request, record) = setup("recovery-unknown-digest", 1);
    let dispatch = database.dispatch();
    update_digest_version(&database, record.call_id);
    let before_connection = database.query_connection();
    let before = sql_snapshot(&before_connection);
    drop(before_connection);

    assert_eq!(
        dispatch.get_prepared(record.call_id),
        Err(gocode_store::provider::ProviderStoreError::CorruptData)
    );

    let after_connection = database.query_connection();
    assert_eq!(sql_snapshot(&after_connection), before);
}

#[test]
fn crash_before_issue_commit_leaves_no_attempt_or_reservation() {
    let (database, request, _record) = setup("recovery-before-issue-commit", 2);
    let execution = database.execution();
    let injection_connection = database.connection();
    install_fault(&injection_connection, Task9FaultPoint::BeforeIssueCommit).unwrap();

    assert_eq!(
        execution.issue(&request),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    drop(execution);
    remove_fault(&injection_connection).unwrap();
    drop(injection_connection);
    let reopened = database.connection();
    for table in [
        "provider_dispatch_attempts",
        "provider_execution_admissions",
        "provider_effect_authorities",
        "provider_budget_reservations",
        "security_authorization_decisions",
        "security_budget_consumptions",
        "security_dispatch_intents",
        "security_audit_pre_effect",
        "security_permit_claims",
    ] {
        assert_eq!(table_count(&reopened, table), 0, "rollback left row in {table}");
    }
    drop(reopened);

    assert!(matches!(
        database.execution().issue(&request),
        Ok(ProviderAuthorityIssueOutcome::Winner(_))
    ));
}
