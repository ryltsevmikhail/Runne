use runne_application::commands::CommandOutcome;
use runne_application::ports::{
    AggregateScope, EventStore, ExecutionNodeId, IdempotencyScope, OperationTag, PrincipalId,
    RuntimeAuthorityId, TaskRunClaimError, TaskRunClaimLookup, TaskRunClaimPort,
};
use runne_application::service::ClaimTaskRunInput;

use super::claim::node_registration;
use super::submit_fence::submit_task_run;
use super::support::*;

pub(super) fn queued(
    database: &Database,
    tail: u8,
) -> (runne_domain::id::TaskRunId, ClaimTaskRunInput) {
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let result = submit_task_run(database, tail, "claim-failure");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = result else {
        panic!("submit outcome expected");
    };
    let (node, epoch) = node_registration(database);
    (
        taskrun_id,
        ClaimTaskRunInput {
            taskrun_id,
            expected_version: 2,
            node_id: ExecutionNodeId(node),
            node_epoch: epoch,
            capability_descriptor: "linux-executor-v1".into(),
            lease_duration_ms: 20_000,
        },
    )
}

#[test]
fn invalid_node_descriptor_epoch_and_version_leave_queued_stream_unchanged() {
    let database = Database::new("taskrun-claim-preconditions");
    let (taskrun_id, input) = queued(&database, 0xa1);
    let context = task_context(0xa2, "claim-preconditions");
    let mut bad_descriptor = input.clone();
    bad_descriptor.capability_descriptor = "linux-executor-v2".into();
    assert!(matches!(
        database
            .task_runs()
            .claim_task_run(&context, bad_descriptor, &database.store),
        Err(runne_application::service::ClaimTaskRunServiceError::Port(
            TaskRunClaimError::CapabilityMismatch
        ))
    ));

    let mut stale_epoch = input.clone();
    stale_epoch.node_epoch += 1;
    assert!(matches!(
        database
            .task_runs()
            .claim_task_run(&context, stale_epoch, &database.store),
        Err(runne_application::service::ClaimTaskRunServiceError::Port(
            TaskRunClaimError::NodeUnavailable
        ))
    ));

    let mut stale_version = input;
    stale_version.expected_version += 1;
    assert!(matches!(
        database
            .task_runs()
            .claim_task_run(&context, stale_version, &database.store),
        Err(
            runne_application::service::ClaimTaskRunServiceError::VersionConflict { actual: 2, .. }
        )
    ));
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        2
    );
    let connection = database.connection();
    for table in [
        "taskrun_assignments",
        "taskrun_fence_counters",
        "taskrun_claim_receipts",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} must remain untouched");
    }
}

#[test]
fn missing_or_expired_node_registration_cannot_claim() {
    let missing = Database::new("taskrun-claim-no-node");
    let (_, missing_input) = queued(&missing, 0xb1);
    let connection = missing.connection();
    connection
        .execute(
            "DELETE FROM execution_nodes WHERE node_id=?1",
            [uuid::Uuid::parse_str(&missing_input.node_id.0)
                .unwrap()
                .as_bytes()],
        )
        .unwrap();
    assert!(matches!(
        missing.task_runs().claim_task_run(
            &task_context(0xb2, "no-node"),
            missing_input,
            &missing.store
        ),
        Err(runne_application::service::ClaimTaskRunServiceError::Port(
            TaskRunClaimError::NodeUnavailable
        ))
    ));

    let expired = Database::new("taskrun-claim-expired-node");
    let (_, expired_input) = queued(&expired, 0xb3);
    let connection = expired.connection();
    connection
        .execute(
            "UPDATE execution_nodes SET heartbeat_at_ms=1,expires_at_ms=2 WHERE node_id=?1",
            [uuid::Uuid::parse_str(&expired_input.node_id.0)
                .unwrap()
                .as_bytes()],
        )
        .unwrap();
    assert!(matches!(
        expired.task_runs().claim_task_run(
            &task_context(0xb4, "expired-node"),
            expired_input,
            &expired.store
        ),
        Err(runne_application::service::ClaimTaskRunServiceError::Port(
            TaskRunClaimError::CorruptData
        ))
    ));
}

#[test]
fn claim_command_id_conflicts_with_an_existing_legacy_receipt() {
    let database = Database::new("taskrun-claim-legacy-command-id");
    let (_, input) = queued(&database, 0xb5);
    let context = task_context(0xb6, "legacy-command-id");
    database
        .connection()
        .execute(
            "INSERT INTO command_receipts VALUES(?1,x'01',x'02',zeroblob(32),x'01',1)",
            [context.command_id.as_bytes()],
        )
        .unwrap();
    assert!(matches!(
        database
            .task_runs()
            .claim_task_run(&context, input, &database.store),
        Err(runne_application::service::ClaimTaskRunServiceError::Port(
            TaskRunClaimError::IdempotencyConflict
        ))
    ));
}

#[test]
fn legacy_receipt_inserts_conflict_with_an_existing_claim_command_id() {
    let database = Database::new("taskrun-claim-global-command-id");
    let (_, input) = queued(&database, 0xb7);
    let context = task_context(0xb8, "global-command-id");
    database
        .task_runs()
        .claim_task_run(&context, input, &database.store)
        .unwrap();
    let connection = database.connection();
    assert!(
        connection
            .execute(
                "INSERT INTO command_receipts VALUES(?1,x'01',x'03',zeroblob(32),x'01',1)",
                [context.command_id.as_bytes()],
            )
            .is_err()
    );
    assert!(connection.execute(
        "INSERT INTO project_workspace_command_receipts VALUES(?1,'authority','owner',1,1,zeroblob(16),'key',zeroblob(32),x'01',1)",
        [context.command_id.as_bytes()],
    ).is_err());
}

#[test]
fn a_late_receipt_write_failure_rolls_back_events_assignment_fence_and_lease() {
    let database = Database::new("taskrun-claim-rollback");
    let (taskrun_id, input) = queued(&database, 0xa3);
    let connection = database.connection();
    connection.execute_batch("CREATE TRIGGER reject_claim_receipt BEFORE INSERT ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'test fault'); END;").unwrap();
    let context = task_context(0xa4, "claim-rollback");
    assert!(matches!(
        database
            .task_runs()
            .claim_task_run(&context, input, &database.store),
        Err(runne_application::service::ClaimTaskRunServiceError::Port(
            TaskRunClaimError::CorruptData
        ))
    ));
    connection
        .execute_batch("DROP TRIGGER reject_claim_receipt;")
        .unwrap();
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        2
    );
    for table in [
        "taskrun_assignments",
        "taskrun_fence_counters",
        "taskrun_claim_receipts",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} must roll back");
    }
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE aggregate_type=1 AND aggregate_id=?1",
                [taskrun_id.as_bytes()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
}

#[test]
fn replay_lookup_rejects_a_receipt_whose_immutable_assignment_was_corrupted() {
    let database = Database::new("taskrun-claim-corrupt-receipt");
    let (taskrun_id, input) = queued(&database, 0xa5);
    let context = task_context(0xa6, "claim-corrupt-receipt");
    database
        .task_runs()
        .claim_task_run(&context, input.clone(), &database.store)
        .unwrap();
    let connection = database.connection();
    connection.execute_batch("DROP TRIGGER taskrun_assignments_immutable; UPDATE taskrun_assignments SET attempt_id=randomblob(16) WHERE taskrun_id=(SELECT taskrun_id FROM taskrun_claim_receipts LIMIT 1);").unwrap();
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"runne-taskrun-claim-v1");
    hasher.update(taskrun_id.as_bytes());
    hasher.update(input.expected_version.to_be_bytes());
    hasher.update((input.node_id.0.len() as u64).to_be_bytes());
    hasher.update(input.node_id.0.as_bytes());
    hasher.update(input.node_epoch.to_be_bytes());
    hasher.update((input.capability_descriptor.len() as u64).to_be_bytes());
    hasher.update(input.capability_descriptor.as_bytes());
    hasher.update(input.lease_duration_ms.to_be_bytes());
    let fingerprint =
        runne_application::fingerprint::CommandFingerprint::from_bytes(hasher.finalize().into());
    let lookup = TaskRunClaimLookup {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key.clone(),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: RuntimeAuthorityId("project-workspace-test-authority".into()),
            principal_id: PrincipalId("owner".into()),
            operation: OperationTag::TaskRunClaim,
            aggregate_scope: AggregateScope::ExistingTaskRun { taskrun_id },
        },
        command_fingerprint: fingerprint,
    };
    assert_eq!(
        database.store.lookup_task_run_claim(lookup),
        Err(TaskRunClaimError::CorruptData)
    );
}
