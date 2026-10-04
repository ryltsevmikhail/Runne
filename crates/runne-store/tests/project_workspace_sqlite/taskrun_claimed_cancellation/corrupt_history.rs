use runne_application::commands::{CancelTaskRunInput, CommandOutcome};
use runne_application::ports::{EventStore, ExecutionNodeId, TaskRunClaimResult};
use runne_domain::id::ConversationId;

use super::super::{claim::node_registration, submit_fence::submit_task_run, support::*};

#[test]
fn cancellation_with_corrupt_conversation_history_fails_closed() {
    let database = Database::new("claimed-cancel-corrupt-conversation-history");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let tail = 0x61;
    let submitted = submit_task_run(&database, tail, "claimed-cancel-corrupt-history");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!("submit commits")
    };
    let (node_id, node_epoch) = node_registration(&database);
    let claim = database
        .task_runs()
        .claim_task_run(
            &task_context(tail + 1, "claimed-cancel-corrupt-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 20_000,
            },
            &database.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claim else {
        panic!("claim commits")
    };
    database
        .task_runs()
        .cancel_task_run(
            &task_context(tail + 2, "claimed-cancel-corrupt-request"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: claim.new_version,
            },
        )
        .unwrap();
    let conversation_id = ConversationId::from_bytes(command(tail + 0x10).into_bytes());
    assert_eq!(
        database
            .connection()
            .execute(
                "DELETE FROM events WHERE aggregate_type=2 AND aggregate_id=?1 AND sequence=1",
                [conversation_id.as_bytes()],
            )
            .unwrap(),
        1
    );

    assert!(
        database
            .task_runs()
            .complete_claimed_taskrun_cancellation(
                &task_context(tail + 3, "claimed-cancel-corrupt-complete"),
                runne_application::ports::CompleteClaimedTaskRunCancellationInput {
                    taskrun_id,
                    expected_version: claim.new_version + 1,
                },
                &database.store,
            )
            .is_err()
    );
    assert_eq!(
        database
            .connection()
            .query_row(
                "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
                rusqlite::params![taskrun_id.as_bytes(), claim.fence.0 as i64],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "active"
    );
}

#[test]
fn claimed_cancellation_does_not_release_when_submit_receipt_is_tampered() {
    let database = Database::new("claimed-cancel-corrupt-submit-receipt");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let tail = 0x71;
    let submitted = submit_task_run(&database, tail, "claimed-cancel-corrupt-submit");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!("submit commits")
    };
    let (node_id, node_epoch) = node_registration(&database);
    let claim = database
        .task_runs()
        .claim_task_run(
            &task_context(tail + 1, "claimed-cancel-corrupt-submit-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 20_000,
            },
            &database.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claim else {
        panic!("claim commits")
    };
    database
        .task_runs()
        .cancel_task_run(
            &task_context(tail + 2, "claimed-cancel-corrupt-submit-request"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: claim.new_version,
            },
        )
        .unwrap();
    database
        .connection()
        .execute(
            "UPDATE command_receipts SET fingerprint=?1 WHERE command_id=(
                SELECT command_id FROM events WHERE aggregate_type=1 AND aggregate_id=?2 AND sequence=1
            )",
            rusqlite::params![vec![0_u8; 32], taskrun_id.as_bytes()],
        )
        .unwrap();

    assert!(
        database
            .task_runs()
            .complete_claimed_taskrun_cancellation(
                &task_context(tail + 3, "claimed-cancel-corrupt-submit-complete"),
                runne_application::ports::CompleteClaimedTaskRunCancellationInput {
                    taskrun_id,
                    expected_version: claim.new_version + 1,
                },
                &database.store,
            )
            .is_err()
    );
    let connection = database.connection();
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
                rusqlite::params![taskrun_id.as_bytes(), claim.fence.0 as i64],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "active"
    );
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        claim.new_version + 1
    );
}
