use runne_application::{
    commands::{CancelTaskRunInput, CommandOutcome, LegacySubmitTaskRunInput},
    conversation_service::ConversationService,
    ports::{TaskRunQueueScanRequest, TaskRunQueueScanner},
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
