#[test]
fn new_issue_after_rotation_gets_new_attempt_and_fence() {
    let (database, old_request, _record) = setup("recovery-new-issue-rotation", 14);
    let old_claim = issue_winner(&database, &old_request);
    let terminal = terminal_request_for_claim(&database, &old_claim, 14);
    let execution = database.execution();
    execution.commit_terminal(&terminal).unwrap();
    let outbox_id = execution.pending_terminal_outbox().unwrap()[0].outbox_id;
    execution.acknowledge_terminal_outbox(outbox_id, [125; 32]).unwrap();
    let before = database.query_connection();
    let old_before = settled_evidence_snapshot(&before, &old_claim);
    drop(before);

    database
        .execution()
        .install_runtime_authority_and_advance_worker_lease(&rotated_runtime_config())
        .unwrap();
    let (new_request, _) = prepared_request(&database, 15);
    let ProviderAuthorityIssueOutcome::Winner(new_admission) = database.execution().issue(&new_request).unwrap()
    else {
        panic!("new call after rotation must issue a new attempt");
    };
    assert_ne!(new_admission.claim().attempt_id, old_claim.attempt_id);
    assert_eq!(new_admission.claim().fencing_token, 14);
    assert_eq!(
        database.execution().issue(&old_request),
        Ok(ProviderAuthorityIssueOutcome::Existing {
            state: runne_provider::ProviderRepositoryState::Settled,
        })
    );
    let after = database.query_connection();
    assert_eq!(settled_evidence_snapshot(&after, &old_claim), old_before);
}
