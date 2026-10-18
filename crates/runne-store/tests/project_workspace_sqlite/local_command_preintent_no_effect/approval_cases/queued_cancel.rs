use super::*;
use crate::project_workspace_sqlite::legacy_local_command_fixture;

async fn queued_cancel_fixture(name: &str, seed: u8) -> (Database, TaskRunId, Vec<u8>) {
    let prepared = legacy_local_command_fixture::prepare(
        name,
        seed,
        seed.wrapping_add(1),
        [0x31; 32],
        [0x32; 32],
    )
    .await;
    let database = prepared.database;
    let taskrun_id = prepared.taskrun_id;
    bind_approval(
        &database,
        taskrun_id,
        &prepared.local,
        prepared.binding,
        seed.wrapping_add(1),
        ApprovalDecision::Approve,
    )
    .await;
    database
        .task_runs()
        .cancel_task_run(
            &task_context(seed.wrapping_add(2), "queued-cancel-proof-negative"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
    let result = database
        .task_runs()
        .complete_queued_cancellation(
            &task_context(
                seed.wrapping_add(4),
                "queued-cancel-proof-negative-complete",
            ),
            CompleteQueuedCancellationInput {
                taskrun_id,
                expected_version: 3,
            },
            &database.store,
        )
        .unwrap();
    assert!(matches!(
        result,
        runne_application::ports::CompleteQueuedCancellationResult::Committed(_)
    ));
    let command_id = database
        .connection()
        .query_row(
            "SELECT command_id FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=4",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    (database, taskrun_id, command_id)
}

#[tokio::test(flavor = "current_thread")]
async fn retained_queued_cancellation_rejects_missing_completion_receipt() {
    let (database, taskrun_id, command_id) =
        queued_cancel_fixture("queued-cancel-missing-receipt", 0xa1).await;
    database
        .connection()
        .execute(
            "DELETE FROM command_receipts WHERE command_id=?1",
            [command_id],
        )
        .unwrap();
    assert!(
        crate::validated_reopen::reopen_store(
            database.file.path(),
            database.identity,
            authority(),
            guard(),
        )
        .is_err()
    );
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        4
    );
}

#[tokio::test(flavor = "current_thread")]
async fn retained_queued_cancellation_rejects_mismatched_completion_receipt() {
    let (database, _, command_id) = queued_cancel_fixture("queued-cancel-bad-receipt", 0xa3).await;
    database
        .connection()
        .execute(
            "UPDATE command_receipts SET fingerprint=zeroblob(32) WHERE command_id=?1",
            [command_id],
        )
        .unwrap();
    assert!(
        crate::validated_reopen::reopen_store(
            database.file.path(),
            database.identity,
            authority(),
            guard(),
        )
        .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn retained_queued_cancellation_rejects_claim_evidence() {
    let (database, taskrun_id, _) =
        queued_cancel_fixture("queued-cancel-claim-evidence", 0xa5).await;
    database
        .connection()
        .execute(
            "INSERT INTO taskrun_fence_counters(taskrun_id,last_fence) VALUES(?1,1)",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    assert!(
        crate::validated_reopen::reopen_store(
            database.file.path(),
            database.identity,
            authority(),
            guard(),
        )
        .is_err()
    );
}
