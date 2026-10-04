use super::*;
use runne_application::ports::{TaskRunNoEffectScanRequest, TaskRunNoEffectScanner};
use runne_domain::task_run::{TaskRun, TaskRunState};

fn cancelling_claim(
    seed: u8,
) -> (
    Database,
    runne_domain::id::TaskRunId,
    TaskRunAssignmentIdentity,
    u64,
) {
    let database = Database::new("no-effect-scan-cancelling-head");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, seed, "cancelled-head-no-effect-scan");
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome
    else {
        panic!("submitted TaskRun")
    };
    let (node_id, old_epoch) = node_registration(&database);
    let (identity, version) = claim(&database, taskrun_id, seed + 1, &node_id, old_epoch);
    database
        .task_runs()
        .cancel_task_run(
            &task_context(seed + 2, "cancel-before-restart-scan"),
            runne_application::commands::CancelTaskRunInput {
                taskrun_id,
                expected_version: version,
            },
        )
        .unwrap();
    (database, taskrun_id, identity, old_epoch)
}

#[test]
fn cancelling_claim_is_not_reclassified_as_never_started() {
    let (database, taskrun_id, identity, old_epoch) = cancelling_claim(0x71);
    let stream = database.store.load_task_run(taskrun_id).unwrap();
    assert_eq!(
        TaskRun::replay(&stream.events).unwrap().state(),
        TaskRunState::Cancelling
    );
    let page = database
        .store
        .scan_no_effect_assignments(
            TaskRunNoEffectScanRequest::new(None, 8, identity.node_id.clone(), old_epoch + 1)
                .unwrap(),
        )
        .unwrap();
    assert!(page.candidates.is_empty());
    assert!(page.reached_end);
    let occupation: String = database
        .connection()
        .query_row(
            "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        occupation, "active",
        "no-effect scan leaves cancellation recovery in charge"
    );
}

#[test]
fn cancelling_head_still_rejects_corrupt_historical_claim_receipt() {
    let (database, taskrun_id, identity, old_epoch) = cancelling_claim(0x74);
    // Keep the already validated managed connection across fault injection. Reopening the
    // database after deliberately breaking an immutable trigger correctly fails validation.
    let connection = database.connection();
    connection
        .execute_batch("DROP TRIGGER taskrun_claim_receipts_immutable;")
        .unwrap();
    connection
        .execute(
            "UPDATE taskrun_claim_receipts SET node_epoch=node_epoch+1 WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64],
        )
        .unwrap();
    let result = database.store.scan_no_effect_assignments(
        TaskRunNoEffectScanRequest::new(None, 8, identity.node_id, old_epoch + 2).unwrap(),
    );
    assert!(matches!(
        result,
        Err(runne_application::ports::EventStoreError::CorruptData)
    ));
    let occupation: String = connection
        .query_row(
            "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(occupation, "active");
}

#[test]
fn cancelling_head_still_rejects_corrupt_event_history() {
    let (database, taskrun_id, identity, old_epoch) = cancelling_claim(0x77);
    // Read, corrupt, scan, and verify through the same managed connection so the
    // assertion observes scanner behavior rather than reopen validation.
    let connection = database.connection();
    connection
        .execute(
            "UPDATE events SET integrity_digest=zeroblob(32) WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=(SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1)",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    let result = database.store.scan_no_effect_assignments(
        TaskRunNoEffectScanRequest::new(None, 8, identity.node_id, old_epoch + 1).unwrap(),
    );
    assert!(matches!(
        result,
        Err(runne_application::ports::EventStoreError::CorruptData)
    ));
    let occupation: String = connection
        .query_row(
            "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(occupation, "active");
}

#[test]
fn eligible_started_head_still_rejects_corrupt_assignment_identity() {
    let database = Database::new("no-effect-scan-corrupt-running-identity");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x74, "corrupt-head-no-effect-scan");
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome
    else {
        panic!("submitted TaskRun")
    };
    let (node_id, old_epoch) = node_registration(&database);
    let (identity, _) = claim(&database, taskrun_id, 0x75, &node_id, old_epoch);
    database
        .connection()
        .execute(
            "UPDATE taskrun_assignment_occupations SET node_epoch=?1 WHERE taskrun_id=?2 AND fence=?3",
            rusqlite::params![old_epoch as i64 + 1, taskrun_id.as_bytes(), identity.fence.0 as i64],
        )
        .unwrap();
    let result = database.store.scan_no_effect_assignments(
        TaskRunNoEffectScanRequest::new(None, 8, identity.node_id, old_epoch + 2).unwrap(),
    );
    assert!(matches!(
        result,
        Err(runne_application::ports::EventStoreError::CorruptData)
    ));
}
