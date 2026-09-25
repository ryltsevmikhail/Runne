use runne_application::commands::CommandOutcome;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    AggregateScope, EventStore, ExecutionNodeId, IdGenerator, IdempotencyScope, OperationTag,
    PrincipalId, TaskRunAssignmentIdentity, TaskRunAssignmentPort, TaskRunClaimResult,
    TaskRunNoEffectReleaseError, TaskRunNoEffectReleasePort, TaskRunNoEffectReleaseRequest,
    TaskRunNoEffectReleaseResult,
};
use runne_domain::event::{Sensitivity, UncommittedEvent};
use runne_domain::id::AggregateId;
use runne_domain::task_run::TaskRunEvent;

use super::claim::node_registration;
use super::submit_fence::submit_task_run;
use super::support::*;

mod integrity;

fn claim(
    database: &Database,
    taskrun: runne_domain::id::TaskRunId,
    tail: u8,
    node: &str,
    epoch: u64,
) -> (TaskRunAssignmentIdentity, u64) {
    let result = database
        .task_runs()
        .claim_task_run(
            &task_context(tail, "release-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id: taskrun,
                expected_version: 2,
                node_id: ExecutionNodeId(node.into()),
                node_epoch: epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 20_000,
            },
            &database.store,
        )
        .unwrap();
    let receipt = match result {
        TaskRunClaimResult::Committed(r) => r,
        _ => panic!("fresh claim"),
    };
    (
        TaskRunAssignmentIdentity {
            taskrun_id: taskrun,
            attempt_id: receipt.attempt_id,
            node_id: receipt.node_id,
            node_epoch: receipt.node_epoch,
            fence: receipt.fence,
        },
        receipt.new_version,
    )
}

fn release_request(
    database: &Database,
    identity: TaskRunAssignmentIdentity,
    version: u64,
    tail: u8,
) -> TaskRunNoEffectReleaseRequest {
    let context = task_context(tail, "no-effect-release");
    let event_id = database.store.next_event_ids(1).unwrap().remove(0);
    let stream = database.store.load_task_run(identity.taskrun_id).unwrap();
    TaskRunNoEffectReleaseRequest {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key.clone(),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: authority(),
            principal_id: PrincipalId("owner".into()),
            operation: OperationTag::TaskRunNoEffectRelease,
            aggregate_scope: AggregateScope::ExistingTaskRun {
                taskrun_id: identity.taskrun_id,
            },
        },
        command_fingerprint: CommandFingerprint::from_bytes([tail; 32]),
        expected_version: version,
        identity: identity.clone(),
        failure_event: UncommittedEvent::from_parts(
            event_id,
            AggregateId::TaskRun(identity.taskrun_id),
            AggregateId::TaskRun(identity.taskrun_id),
            stream.last_event_id,
            context.command_id,
            context.idempotency_key,
            1,
            context.actor,
            Sensitivity::Public,
            TaskRunEvent::TaskRunFailed {
                reason: "dispatch_not_started".into(),
            },
        ),
    }
}

#[test]
fn release_replays_and_frees_node_capacity() {
    let database = Database::new("taskrun-no-effect-release");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let first = submit_task_run(&database, 0xc1, "release-first");
    let second = submit_task_run(&database, 0xc2, "release-second");
    let CommandOutcome::TaskRunSubmitted {
        taskrun_id: first, ..
    } = first
    else {
        panic!()
    };
    let CommandOutcome::TaskRunSubmitted {
        taskrun_id: second, ..
    } = second
    else {
        panic!()
    };
    let (node, epoch) = node_registration(&database);
    let (identity, version) = claim(&database, first, 0xc3, &node, epoch);
    let request = release_request(&database, identity.clone(), version, 0xc4);
    let released = database
        .store
        .release_taskrun_no_effect(request.clone())
        .unwrap();
    let TaskRunNoEffectReleaseResult::Released(receipt) = released else {
        panic!("release")
    };
    assert_eq!(
        database.store.release_taskrun_no_effect(request).unwrap(),
        TaskRunNoEffectReleaseResult::Duplicate(receipt)
    );
    let second_claim = database
        .task_runs()
        .claim_task_run(
            &task_context(0xc5, "second-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id: second,
                expected_version: 2,
                node_id: ExecutionNodeId(node),
                node_epoch: epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 20_000,
            },
            &database.store,
        )
        .unwrap();
    assert!(matches!(second_claim, TaskRunClaimResult::Committed(_)));
}

#[test]
fn release_rejects_stale_expected_version_without_mutation() {
    let database = Database::new("taskrun-release-stale-version");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let result = submit_task_run(&database, 0x31, "release-stale-version");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = result else {
        panic!()
    };
    let (node, epoch) = node_registration(&database);
    let (identity, version) = claim(&database, taskrun_id, 0x32, &node, epoch);
    let mut request = release_request(&database, identity.clone(), version, 0x33);
    request.expected_version -= 1;

    assert_eq!(
        database.store.release_taskrun_no_effect(request),
        Err(TaskRunNoEffectReleaseError::StaleVersion {
            expected: version - 1,
            actual: version,
        })
    );
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
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "active");
}

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
