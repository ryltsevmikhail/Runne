use super::claim::node_registration;
use super::fence::create_task_run;
use super::submit_fence::submit_task_run;
use super::support::*;
use runne_application::commands::CommandOutcome;
use runne_application::ports::{
    ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunClaimResult,
    TaskRunExecutionInputError as Error, TaskRunExecutionInputPort,
};

pub(super) fn claim(
    database: &Database,
    taskrun_id: runne_domain::id::TaskRunId,
    tail: u8,
) -> TaskRunAssignmentIdentity {
    let (node_id, node_epoch) = node_registration(database);
    let result = database
        .task_runs()
        .claim_task_run(
            &task_context(tail, "execution-input-claim"),
            runne_application::service::ClaimTaskRunInput {
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
    let receipt = match result {
        TaskRunClaimResult::Committed(value) => value,
        _ => panic!("fresh claim"),
    };
    TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: receipt.attempt_id,
        node_id: ExecutionNodeId(node_id),
        node_epoch,
        fence: receipt.fence,
    }
}

#[test]
fn reads_only_exact_v2_submitted_input_and_redacts_debug() {
    let database = Database::new("execution-input-v2");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submit_task_run(&database, 0x31, "input-v2")
    else {
        panic!("submitted")
    };
    let identity = claim(&database, taskrun_id, 0x32);
    let value = database
        .store
        .read_taskrun_execution_input(identity, 4)
        .unwrap();
    assert_eq!(value.input.prompt(), "test prompt");
    assert_eq!(value.stream_version, 4);
    assert!(!format!("{value:?}").contains("test prompt"));
}

#[test]
fn legacy_created_input_is_blocked_and_stale_versions_fail_closed() {
    let database = Database::new("execution-input-legacy");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let legacy_id = create_task_run(&database, 0x33);
    database
        .task_runs()
        .queue_task_run(
            &task_context(0x3c, "queue-legacy"),
            runne_application::commands::QueueTaskRunInput {
                taskrun_id: legacy_id,
                expected_version: 1,
            },
        )
        .unwrap();
    let legacy_identity = claim(&database, legacy_id, 0x34);
    assert_eq!(
        database
            .store
            .read_taskrun_execution_input(legacy_identity.clone(), 4),
        Err(Error::UnsupportedInput)
    );

    assert_eq!(
        database
            .store
            .read_taskrun_execution_input(legacy_identity.clone(), 3),
        Err(Error::StaleVersion)
    );
    let mut wrong = legacy_identity;
    wrong.attempt_id = runne_domain::id::AttemptId::from_bytes(command(0x99).into_bytes());
    assert_eq!(
        database.store.read_taskrun_execution_input(wrong, 4),
        Err(Error::StaleAssignment)
    );
}

#[test]
fn cancelled_or_advanced_stream_and_digest_tamper_are_rejected() {
    let database = Database::new("execution-input-advanced");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submit_task_run(&database, 0x37, "input-advanced")
    else {
        panic!("submitted")
    };
    let identity = claim(&database, taskrun_id, 0x38);
    let context = task_context(0x39, "cancel-input");
    database
        .task_runs()
        .cancel_task_run(
            &context,
            runne_application::commands::CancelTaskRunInput {
                taskrun_id,
                expected_version: 4,
            },
        )
        .unwrap();
    assert!(matches!(
        database
            .store
            .read_taskrun_execution_input(identity.clone(), 4),
        Err(Error::StaleVersion | Error::StaleAssignment | Error::NotExecutable)
    ));

    let tamper_database = Database::new("execution-input-tamper");
    let repository = tamper_database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submit_task_run(&tamper_database, 0x3a, "input-tamper")
    else {
        panic!("submitted")
    };
    let identity = claim(&tamper_database, taskrun_id, 0x3b);
    tamper_database.connection().execute("UPDATE events SET integrity_digest=zeroblob(32) WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1", [taskrun_id.as_bytes()]).unwrap();
    assert_eq!(
        tamper_database
            .store
            .read_taskrun_execution_input(identity, 4),
        Err(Error::CorruptData)
    );
}

#[test]
fn expired_or_inactive_occupation_and_stale_fence_are_rejected() {
    let expired_database = Database::new("execution-input-expired-occupation");
    let repository = expired_database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submit_task_run(&expired_database, 0x41, "input-expired")
    else {
        panic!("submitted")
    };
    let identity = claim(&expired_database, taskrun_id, 0x42);
    expired_database.connection().execute(
        "UPDATE taskrun_assignment_occupations SET lease_expires_at_ms=1 WHERE taskrun_id=?1 AND fence=?2",
        rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64],
    ).unwrap();
    assert_eq!(
        expired_database
            .store
            .read_taskrun_execution_input(identity, 4),
        Err(Error::StaleAssignment)
    );

    let inactive_database = Database::new("execution-input-inactive-occupation");
    let repository = inactive_database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submit_task_run(&inactive_database, 0x43, "input-inactive")
    else {
        panic!("submitted")
    };
    let identity = claim(&inactive_database, taskrun_id, 0x44);
    inactive_database.connection().execute(
        "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1 WHERE taskrun_id=?2 AND fence=?3",
        rusqlite::params![[0x45_u8; 16].as_slice(), taskrun_id.as_bytes(), identity.fence.0 as i64],
    ).unwrap();
    assert_eq!(
        inactive_database
            .store
            .read_taskrun_execution_input(identity, 4),
        Err(Error::StaleAssignment)
    );

    let stale_database = Database::new("execution-input-stale-fence");
    let repository = stale_database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submit_task_run(&stale_database, 0x46, "input-stale-fence")
    else {
        panic!("submitted")
    };
    let identity = claim(&stale_database, taskrun_id, 0x47);
    let stale = TaskRunAssignmentIdentity {
        fence: runne_application::ports::TaskRunFence(identity.fence.0 + 1),
        ..identity
    };
    assert_eq!(
        stale_database.store.read_taskrun_execution_input(stale, 4),
        Err(Error::StaleAssignment)
    );
}
