use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, CancelTaskRunInput,
    CommandOutcome,
};
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    EventStore, ExecutionNodeId, TaskRunCancellationScanner, TaskRunClaimResult,
    TaskRunQueueScanRequest,
};
use runne_domain::id::{ConversationId, WorkspaceId};
use runne_domain::message::MessageText;

use super::{claim::node_registration, submit_fence::submit_task_run, support::*};

#[test]
fn cancellation_after_claim_before_text_begin_releases_exact_occupation() {
    let database = Database::new("claimed-cancel-before-text-begin");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let tail = 0x41;
    let submitted = submit_task_run(&database, tail, "claimed-cancel-before-begin");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!("submit commits")
    };
    let (node_id, node_epoch) = node_registration(&database);
    let claim = database
        .task_runs()
        .claim_task_run(
            &task_context(tail + 1, "claimed-cancel-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
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
            &task_context(tail + 2, "claimed-cancel-request"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: claim.new_version,
            },
        )
        .unwrap();
    let pending = database
        .store
        .scan_pending_taskrun_cancellations(TaskRunQueueScanRequest::new(None, 32).unwrap())
        .unwrap();
    assert!(
        pending
            .candidates
            .iter()
            .any(|candidate| candidate.taskrun_id == taskrun_id)
    );
    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    assert!(
        reopened
            .scan_pending_taskrun_cancellations(TaskRunQueueScanRequest::new(None, 32).unwrap())
            .unwrap()
            .candidates
            .iter()
            .any(|candidate| candidate.taskrun_id == taskrun_id)
    );
    let context = task_context(tail + 3, "claimed-cancel-complete");
    let reopened_task_runs = runne_application::service::TaskRunService::new(
        reopened.clone(),
        reopened.clone(),
        reopened.clone(),
        authority(),
    );
    let completed = reopened_task_runs
        .complete_claimed_taskrun_cancellation(
            &context,
            runne_application::ports::CompleteClaimedTaskRunCancellationInput {
                taskrun_id,
                expected_version: claim.new_version + 1,
            },
            &reopened,
        )
        .unwrap();
    let runne_application::ports::CompleteQueuedCancellationResult::Committed(receipt) = completed
    else {
        panic!("claimed cancellation settles")
    };
    assert_eq!(receipt.new_version, claim.new_version + 2);
    let state = runne_domain::task_run::TaskRun::replay(
        &database.store.load_task_run(taskrun_id).unwrap().events,
    )
    .unwrap()
    .state();
    assert_eq!(state, runne_domain::task_run::TaskRunState::Cancelled);
    let connection = database.connection();
    let occupation: (String, Vec<u8>) = connection.query_row(
        "SELECT state,release_event_id FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
        rusqlite::params![taskrun_id.as_bytes(), claim.fence.0 as i64],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(occupation.0, "released");
    assert_eq!(
        occupation.1.as_slice(),
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .last_event_id
            .unwrap()
            .as_bytes()
    );
    assert_eq!(connection.query_row(
        "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1 AND fence=?2",
        rusqlite::params![taskrun_id.as_bytes(), claim.fence.0 as i64], |row| row.get::<_, i64>(0),
    ).unwrap(), 1);
    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    assert_eq!(
        reopened.load_task_run(taskrun_id).unwrap().current_version,
        receipt.new_version
    );
    assert!(
        !reopened
            .scan_pending_taskrun_cancellations(TaskRunQueueScanRequest::new(None, 32).unwrap())
            .unwrap()
            .candidates
            .iter()
            .any(|candidate| candidate.taskrun_id == taskrun_id)
    );

    let next = submit_task_run(&database, tail + 0x10, "claimed-cancel-next-slot");
    let CommandOutcome::TaskRunSubmitted {
        taskrun_id: next_id,
        ..
    } = next
    else {
        panic!()
    };
    assert!(matches!(
        database
            .task_runs()
            .claim_task_run(
                &task_context(tail + 0x11, "claimed-cancel-next-slot-claim"),
                runne_application::service::ClaimTaskRunInput {
                    taskrun_id: next_id,
                    expected_version: 2,
                    node_id: ExecutionNodeId(node_id),
                    node_epoch,
                    capability_descriptor: "linux-executor-v1".into(),
                    lease_duration_ms: 20_000,
                },
                &database.store,
            )
            .unwrap(),
        TaskRunClaimResult::Committed(_)
    ));
}

#[test]
fn cancellation_after_text_begin_remains_pending_and_occupied() {
    let database = Database::new("claimed-cancel-after-text-begin");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let tail = 0x51;
    let submitted = submit_task_run(&database, tail, "claimed-cancel-after-begin");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!()
    };
    let conversation_id = ConversationId::from_bytes(command(tail + 0x10).into_bytes());
    let (node_id, node_epoch) = node_registration(&database);
    let claim = database
        .task_runs()
        .claim_task_run(
            &task_context(tail + 1, "claimed-cancel-after-begin-claim"),
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
        panic!()
    };
    let text = ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        authority(),
        guard(),
    );
    text.begin_claimed_text(
        &task_context(tail + 2, "claimed-cancel-text-begin"),
        BeginClaimedConversationTextInput {
            original: BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("test prompt").unwrap(),
            },
            taskrun_id,
            attempt_id: claim.attempt_id,
            taskrun_version: claim.new_version,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            assignment: runne_application::ports::TaskRunAssignmentIdentity {
                taskrun_id,
                attempt_id: claim.attempt_id,
                node_id: claim.node_id.clone(),
                node_epoch: claim.node_epoch,
                fence: claim.fence,
            },
        },
    )
    .unwrap();
    database
        .task_runs()
        .cancel_task_run(
            &task_context(tail + 3, "claimed-cancel-after-begin-request"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: claim.new_version,
            },
        )
        .unwrap();
    assert!(
        database
            .task_runs()
            .complete_claimed_taskrun_cancellation(
                &task_context(tail + 4, "claimed-cancel-after-begin-complete"),
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

#[path = "taskrun_claimed_cancellation/corrupt_history.rs"]
mod corrupt_history;
