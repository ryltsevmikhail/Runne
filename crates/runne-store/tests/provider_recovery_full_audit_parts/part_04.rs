use runne_provider::ProviderRepositoryState;

#[test]
fn duplicate_client_retry_issue_returns_existing_without_new_rows() {
    let (database, request, _record) = setup("recovery-duplicate-issue", 6);
    let _claim = issue_winner(&database, &request);
    let before_connection = database.query_connection();
    let before = sql_snapshot(&before_connection);
    drop(before_connection);

    assert_eq!(
        database.issue(&request),
        Ok(ProviderAuthorityIssueOutcome::Existing {
            state: ProviderRepositoryState::Dispatching,
        })
    );
    let after_exact = database.query_connection();
    assert_eq!(sql_snapshot(&after_exact), before);
    drop(after_exact);

    let mut conflicting = request.clone();
    conflicting.requested_output_tokens -= 1;
    assert_eq!(
        database.issue(&conflicting),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    let after_conflict = database.query_connection();
    assert_eq!(sql_snapshot(&after_conflict), before);
}
