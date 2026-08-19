#[test]
fn uncertain_attempt_is_never_redispatched_through_recovery_paths() {
    let (database, request, _record) = setup("recovery-uncertain-replay", 10);
    let claim = issue_winner(&database, &request);
    let dispatch = database.dispatch();
    assert_eq!(
        dispatch.recover_attempt(
            claim.attempt_id,
            claim.fencing_token,
            ProviderDispatchState::Dispatching,
        ),
        Ok(runne_store::provider::RecoveryCasOutcome::TransitionedToUncertain)
    );
    let before = database.query_connection();
    let before = sql_snapshot(&before);

    assert_eq!(
        dispatch.recover_attempt(
            claim.attempt_id,
            claim.fencing_token,
            ProviderDispatchState::Dispatching,
        ),
        Ok(runne_store::provider::RecoveryCasOutcome::AlreadyUncertain)
    );
    assert_eq!(
        dispatch.mark_uncertain(claim.attempt_id, claim.fencing_token),
        Ok(ProviderDispatchState::Uncertain)
    );
    assert_eq!(
        database.execution().issue(&request),
        Ok(ProviderAuthorityIssueOutcome::Existing {
            state: runne_provider::ProviderRepositoryState::Uncertain,
        })
    );
    assert_eq!(effect_start_count(&database.query_connection()), 0);
    let after = database.query_connection();
    assert_eq!(sql_snapshot(&after), before);
}
