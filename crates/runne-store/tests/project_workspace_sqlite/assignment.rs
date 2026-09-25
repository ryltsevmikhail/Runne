use runne_application::commands::{CancelTaskRunInput, CommandOutcome};
use runne_application::ports::{
    ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunAssignmentPort, TaskRunClaimResult,
    TaskRunDispatchIntentResult, TaskRunFence, TaskRunLeaseRenewal,
};
use runne_application::service::ClaimTaskRunInput;

use super::claim::node_registration;
use super::submit_fence::submit_task_run;
use super::support::*;

#[test]
fn assignment_dispatch_prepare_and_lease_renewal_are_exact_and_idempotent() {
    let database = Database::new("taskrun-assignment-lifecycle");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x97, "assignment-lifecycle-source");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submit outcome expected");
    };
    let (node_id, node_epoch) = node_registration(&database);
    let context = task_context(0x98, "assignment-lifecycle-claim");
    let claim = database
        .task_runs()
        .claim_task_run(
            &context,
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &database.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(receipt) = claim else {
        panic!("claim expected");
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: receipt.attempt_id,
        node_id: ExecutionNodeId(node_id),
        node_epoch,
        fence: receipt.fence,
    };
    let colliding_renewal = TaskRunLeaseRenewal {
        identity: identity.clone(),
        renewal_id: context.command_id,
        lease_duration_ms: 30_000,
    };
    assert_eq!(
        database
            .store
            .renew_taskrun_assignment_lease(colliding_renewal),
        Err(runne_application::ports::TaskRunAssignmentError::IdempotencyConflict)
    );
    {
        let connection = database.connection();
        connection.execute("UPDATE taskrun_assignment_occupations SET dispatch_intent='unknown' WHERE taskrun_id=?1 AND fence=?2", rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64]).unwrap();
    }
    assert_eq!(
        database.store.prepare_taskrun_dispatch(identity.clone()),
        Err(runne_application::ports::TaskRunAssignmentError::StaleAssignment)
    );
    {
        let connection = database.connection();
        connection.execute("UPDATE taskrun_assignment_occupations SET dispatch_intent='absent' WHERE taskrun_id=?1 AND fence=?2", rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64]).unwrap();
    }
    assert_eq!(
        database
            .store
            .prepare_taskrun_dispatch(identity.clone())
            .unwrap(),
        TaskRunDispatchIntentResult::Prepared
    );
    assert_eq!(
        database
            .store
            .prepare_taskrun_dispatch(identity.clone())
            .unwrap(),
        TaskRunDispatchIntentResult::Duplicate
    );
    let renewal = TaskRunLeaseRenewal {
        identity: identity.clone(),
        renewal_id: runne_domain::id::CommandId::from_bytes([0x99; 16]),
        lease_duration_ms: 30_000,
    };
    let existing_expiry = {
        let connection = database.connection();
        let expiry: i64 = connection
            .query_row(
                "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)+120000",
                [],
                |row| row.get(0),
            )
            .unwrap();
        connection
            .execute(
                "UPDATE taskrun_assignment_occupations SET lease_expires_at_ms=?1 WHERE taskrun_id=?2 AND fence=?3",
                rusqlite::params![expiry, taskrun_id.as_bytes(), identity.fence.0 as i64],
            )
            .unwrap();
        expiry
    };
    let renewed = database
        .store
        .renew_taskrun_assignment_lease(renewal.clone())
        .unwrap();
    assert_eq!(
        renewed.lease_expires_at.as_unix_micros(),
        existing_expiry * 1_000
    );
    assert_eq!(
        database
            .store
            .renew_taskrun_assignment_lease(renewal.clone())
            .unwrap(),
        renewed
    );
    let stale = TaskRunAssignmentIdentity {
        fence: TaskRunFence(identity.fence.0 + 1),
        ..identity.clone()
    };
    assert_eq!(
        database.store.prepare_taskrun_dispatch(stale),
        Err(runne_application::ports::TaskRunAssignmentError::StaleAssignment)
    );
    let stale_epoch = TaskRunAssignmentIdentity {
        node_epoch: node_epoch + 1,
        ..identity.clone()
    };
    assert_eq!(
        database.store.prepare_taskrun_dispatch(stale_epoch),
        Err(runne_application::ports::TaskRunAssignmentError::StaleAssignment)
    );
    {
        let connection = database.connection();
        connection.execute("UPDATE taskrun_assignment_occupations SET lease_expires_at_ms=1 WHERE taskrun_id=?1 AND fence=?2", rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64]).unwrap();
    }
    let expired = TaskRunLeaseRenewal {
        identity,
        renewal_id: runne_domain::id::CommandId::from_bytes([0x9a; 16]),
        lease_duration_ms: 30_000,
    };
    assert_eq!(
        database.store.renew_taskrun_assignment_lease(expired),
        Err(runne_application::ports::TaskRunAssignmentError::LeaseExpired)
    );
    assert_eq!(
        database.store.renew_taskrun_assignment_lease(renewal),
        Err(runne_application::ports::TaskRunAssignmentError::LeaseExpired)
    );
}

#[test]
fn dispatch_and_renewal_replay_reject_a_cancelled_taskrun() {
    let database = Database::new("taskrun-assignment-cancelled");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x9b, "assignment-cancel-source");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submit outcome expected");
    };
    let (node_id, node_epoch) = node_registration(&database);
    let context = task_context(0x9c, "assignment-cancel-claim");
    let TaskRunClaimResult::Committed(receipt) = database
        .task_runs()
        .claim_task_run(
            &context,
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &database.store,
        )
        .unwrap()
    else {
        panic!("claim expected");
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: receipt.attempt_id,
        node_id: ExecutionNodeId(node_id),
        node_epoch,
        fence: receipt.fence,
    };
    database
        .store
        .prepare_taskrun_dispatch(identity.clone())
        .unwrap();
    let renewal = TaskRunLeaseRenewal {
        identity: identity.clone(),
        renewal_id: runne_domain::id::CommandId::from_bytes([0x9d; 16]),
        lease_duration_ms: 30_000,
    };
    database
        .store
        .renew_taskrun_assignment_lease(renewal.clone())
        .unwrap();
    database
        .task_runs()
        .cancel_task_run(
            &task_context(0x9e, "assignment-cancel-run"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 4,
            },
        )
        .unwrap();
    assert_eq!(
        database.store.prepare_taskrun_dispatch(identity.clone()),
        Err(runne_application::ports::TaskRunAssignmentError::StaleAssignment)
    );
    assert_eq!(
        database.store.renew_taskrun_assignment_lease(renewal),
        Err(runne_application::ports::TaskRunAssignmentError::StaleAssignment)
    );
}

#[test]
fn dispatch_and_renewal_reject_a_missing_claim_event() {
    let database = Database::new("taskrun-assignment-corrupt-stream");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x9f, "assignment-corrupt-source");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submit outcome expected");
    };
    let (node_id, node_epoch) = node_registration(&database);
    let TaskRunClaimResult::Committed(receipt) = database
        .task_runs()
        .claim_task_run(
            &task_context(0xa0, "assignment-corrupt-claim"),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &database.store,
        )
        .unwrap()
    else {
        panic!("claim expected");
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: receipt.attempt_id,
        node_id: ExecutionNodeId(node_id),
        node_epoch,
        fence: receipt.fence,
    };
    database
        .connection()
        .execute(
            "DELETE FROM events WHERE event_id=?1",
            [receipt.started_event_id.as_bytes()],
        )
        .unwrap();
    assert_eq!(
        database.store.prepare_taskrun_dispatch(identity.clone()),
        Err(runne_application::ports::TaskRunAssignmentError::CorruptData)
    );
    assert_eq!(
        database
            .store
            .renew_taskrun_assignment_lease(TaskRunLeaseRenewal {
                identity,
                renewal_id: runne_domain::id::CommandId::from_bytes([0xa1; 16]),
                lease_duration_ms: 30_000,
            }),
        Err(runne_application::ports::TaskRunAssignmentError::CorruptData)
    );
}
