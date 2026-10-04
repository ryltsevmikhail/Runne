use runne_application::{
    commands::{CancelTaskRunInput, CommandOutcome, LegacySubmitTaskRunInput},
    conversation_service::ConversationService,
    ports::{
        AggregateScope, CompleteQueuedCancellationInput, CompleteQueuedCancellationRequest,
        EventStore, IdGenerator, IdempotencyScope, OperationTag, TaskRunCancellationCompletionPort,
        TaskRunQueueScanRequest, TaskRunQueueScanner,
    },
};
use runne_domain::id::{ConversationId, WorkspaceId};

use super::{submit_fence::submit_task_run, support::*};

fn legacy_submit(database: &Database) -> runne_domain::id::TaskRunId {
    let conversation_id = ConversationId::from_bytes(command(0x11).into_bytes());
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context(0x12, "queue-legacy-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(0x12),
                idempotency_key: key("queue-legacy-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let outcome = database
        .task_runs()
        .submit_task_run_legacy(
            &task_context(0x13, "queue-legacy-submit"),
            LegacySubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("legacy submit outcome expected");
    };
    taskrun_id
}

#[test]
fn pages_advance_over_legacy_and_nonqueued_runs_and_return_only_queued_v2() {
    let database = Database::new("taskrun-queue-scan-pages");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let legacy = legacy_submit(&database);
    let queued = submit_task_run(&database, 0x41, "queue-v2");
    let CommandOutcome::TaskRunSubmitted {
        taskrun_id: queued, ..
    } = queued
    else {
        panic!("v2 submit outcome expected");
    };
    let cancelled = submit_task_run(&database, 0x51, "queue-cancelled");
    let CommandOutcome::TaskRunSubmitted {
        taskrun_id: cancelled,
        ..
    } = cancelled
    else {
        panic!("v2 submit outcome expected");
    };
    database
        .task_runs()
        .cancel_task_run(
            &task_context(0x52, "queue-cancel"),
            CancelTaskRunInput {
                taskrun_id: cancelled,
                expected_version: 2,
            },
        )
        .unwrap();

    let mut cursor = None;
    let mut seen = Vec::new();
    loop {
        let page = database
            .store
            .scan_queued_task_runs(TaskRunQueueScanRequest::new(cursor, 1).unwrap())
            .unwrap();
        assert_eq!(page.examined, 1);
        assert!(page.next_cursor > cursor);
        seen.extend(page.candidates);
        cursor = page.next_cursor;
        if page.reached_end {
            break;
        }
    }
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].taskrun_id, queued);
    assert_eq!(seen[0].current_version, 2);
    assert_ne!(seen[0].taskrun_id, legacy);
    assert_ne!(seen[0].taskrun_id, cancelled);
}

#[test]
fn scan_fails_closed_on_corrupt_examined_stream() {
    let database = Database::new("taskrun-queue-scan-corrupt");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x61, "queue-corrupt");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submit outcome expected");
    };
    database.connection().execute(
        "UPDATE events SET sequence = 4 WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 1",
        [taskrun_id.as_bytes()],
    ).unwrap();
    assert_eq!(
        database
            .store
            .scan_queued_task_runs(TaskRunQueueScanRequest::new(None, 1).unwrap())
            .unwrap_err(),
        runne_application::ports::EventStoreError::CorruptData
    );
}

#[test]
fn scan_fails_closed_on_corrupt_stream_head_timestamp() {
    let database = Database::new("taskrun-queue-scan-corrupt-head-time");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x71, "queue-corrupt-head-time");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submit outcome expected");
    };
    database
        .connection()
        .execute(
            "UPDATE aggregate_streams SET last_timestamp = last_timestamp + 1
         WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    assert_eq!(
        database
            .store
            .scan_queued_task_runs(TaskRunQueueScanRequest::new(None, 1).unwrap())
            .unwrap_err(),
        runne_application::ports::EventStoreError::CorruptData
    );
}

#[test]
fn scan_fails_closed_on_invalid_raw_event_text_metadata() {
    let database = Database::new("taskrun-queue-scan-invalid-text");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x72, "queue-invalid-text");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submit outcome expected");
    };
    database.connection().execute(
        "UPDATE events SET actor = X'ff' WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = 1",
        [taskrun_id.as_bytes()],
    ).unwrap();
    assert_eq!(
        database
            .store
            .scan_queued_task_runs(TaskRunQueueScanRequest::new(None, 1).unwrap())
            .unwrap_err(),
        runne_application::ports::EventStoreError::CorruptData
    );
}

#[test]
fn queued_cancellation_terminalizes_and_claimed_runs_cannot_use_the_path() {
    let database = Database::new("queued-cancellation-completion");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let submitted = submit_task_run(&database, 0x21, "cancel-complete");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!()
    };
    database
        .task_runs()
        .cancel_task_run(
            &task_context(0x22, "cancel-request"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
    let completed = database
        .task_runs()
        .complete_queued_cancellation(
            &task_context(0x23, "cancel-completed"),
            CompleteQueuedCancellationInput {
                taskrun_id,
                expected_version: 3,
            },
            &database.store,
        )
        .unwrap();
    let runne_application::ports::CompleteQueuedCancellationResult::Committed(receipt) = completed
    else {
        panic!()
    };
    assert_eq!(receipt.new_version, 4);
    let stream = database.store.load_task_run(taskrun_id).unwrap();
    assert_eq!(stream.current_version, 4);
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(&stream.events)
            .unwrap()
            .state(),
        runne_domain::task_run::TaskRunState::Cancelled
    );
    assert!(matches!(
        stream.events.last().unwrap().payload(),
        runne_domain::task_run::TaskRunEvent::CancellationCompleted
    ));

    let submitted = submit_task_run(&database, 0x31, "claimed-before-cancel-complete");
    let CommandOutcome::TaskRunSubmitted {
        taskrun_id: claimed_id,
        ..
    } = submitted
    else {
        panic!()
    };
    let (node_id, node_epoch) = super::claim::node_registration(&database);
    let claimed = database
        .task_runs()
        .claim_task_run(
            &task_context(0x32, "cancellation-claimed-run"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id: claimed_id,
                expected_version: 2,
                node_id: runne_application::ports::ExecutionNodeId(node_id),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 20_000,
            },
            &database.store,
        )
        .unwrap();
    assert!(matches!(
        claimed,
        runne_application::ports::TaskRunClaimResult::Committed(_)
    ));
    let context = task_context(0x33, "wrongly-complete-claimed");
    let claimed_stream = database.store.load_task_run(claimed_id).unwrap();
    let event = runne_domain::event::UncommittedEvent::from_parts(
        database.store.next_event_ids(1).unwrap().remove(0),
        runne_domain::id::AggregateId::TaskRun(claimed_id),
        runne_domain::id::AggregateId::TaskRun(claimed_id),
        claimed_stream.last_event_id,
        context.command_id,
        context.idempotency_key.clone(),
        1,
        context.actor.clone(),
        runne_domain::event::Sensitivity::Public,
        runne_domain::task_run::TaskRunEvent::CancellationCompleted,
    );
    let error = database
        .store
        .complete_queued_cancellation(CompleteQueuedCancellationRequest {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            idempotency_scope: IdempotencyScope {
                runtime_authority_id: authority(),
                principal_id: context.principal_id,
                operation: OperationTag::CompleteQueuedCancellation,
                aggregate_scope: AggregateScope::ExistingTaskRun {
                    taskrun_id: claimed_id,
                },
            },
            command_fingerprint: runne_application::fingerprint::CommandFingerprint::from_bytes(
                [0x44; 32],
            ),
            expected_version: claimed_stream.current_version,
            cancellation_completed: event,
        })
        .unwrap_err();
    assert_eq!(
        error,
        runne_application::ports::CompleteQueuedCancellationError::AlreadyClaimed
    );
    assert_eq!(
        database
            .store
            .load_task_run(claimed_id)
            .unwrap()
            .current_version,
        claimed_stream.current_version
    );
}
