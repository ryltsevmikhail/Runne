use super::*;

#[test]
fn present_and_unknown_intents_never_release_capacity() {
    let database = Database::new("taskrun-release-intent");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let result = submit_task_run(&database, 0xd1, "release-present");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = result else {
        panic!()
    };
    let (node, epoch) = node_registration(&database);
    let (identity, version) = claim(&database, taskrun_id, 0xd2, &node, epoch);
    database
        .store
        .prepare_taskrun_dispatch(identity.clone())
        .unwrap();
    assert_eq!(
        database
            .store
            .release_taskrun_no_effect(release_request(&database, identity, version, 0xd3)),
        Err(TaskRunNoEffectReleaseError::DispatchMayHaveStarted)
    );

    let unknown = Database::new("taskrun-release-unknown-intent");
    let repository = unknown.repository();
    create_project(&repository);
    create_workspace(&repository);
    let result = submit_task_run(&unknown, 0xd4, "release-unknown");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = result else {
        panic!()
    };
    let (node, epoch) = node_registration(&unknown);
    let (identity, version) = claim(&unknown, taskrun_id, 0xd5, &node, epoch);
    let connection = unknown.connection();
    connection
        .execute_batch("DROP TRIGGER taskrun_occupation_intent_guard;")
        .unwrap();
    connection.execute("UPDATE taskrun_assignment_occupations SET dispatch_intent='unknown' WHERE taskrun_id=?1 AND fence=?2",rusqlite::params![identity.taskrun_id.as_bytes(),identity.fence.0 as i64]).unwrap();
    assert_eq!(
        unknown
            .store
            .release_taskrun_no_effect(release_request(&unknown, identity, version, 0xd6)),
        Err(TaskRunNoEffectReleaseError::DispatchMayHaveStarted)
    );
}

#[test]
fn late_receipt_failure_rolls_back_event_and_occupation_release() {
    let database = Database::new("taskrun-release-rollback");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let result = submit_task_run(&database, 0x61, "release-rollback");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = result else {
        panic!()
    };
    let (node, epoch) = node_registration(&database);
    let (identity, version) = claim(&database, taskrun_id, 0x62, &node, epoch);
    let request = release_request(&database, identity.clone(), version, 0x63);
    database.connection().execute_batch("CREATE TRIGGER reject_release BEFORE INSERT ON taskrun_no_effect_release_receipts BEGIN SELECT RAISE(ABORT,'injected release receipt failure'); END;").unwrap();
    assert!(matches!(
        database.store.release_taskrun_no_effect(request),
        Err(TaskRunNoEffectReleaseError::IdempotencyConflict)
    ));
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        version
    );
    let state: String = database
        .connection()
        .query_row(
            "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "active");
}
