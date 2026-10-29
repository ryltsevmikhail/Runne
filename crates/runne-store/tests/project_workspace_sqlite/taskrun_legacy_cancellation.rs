use runne_application::fingerprint::CommandFingerprint;
use runne_application::{
    commands::{CancelTaskRunInput, CommandOutcome, LegacySubmitTaskRunInput},
    conversation_service::ConversationService,
    ports::{
        AggregateScope, CompleteQueuedCancellationInput, CompleteQueuedCancellationRequest,
        CompleteQueuedCancellationResult, EventStore, IdempotencyScope, OperationTag,
        TaskRunCancellationCompletionPort, TaskRunCancellationScanner, TaskRunQueueScanRequest,
    },
};
use runne_domain::event::Sensitivity;
use runne_domain::{
    event::UncommittedEvent,
    id::{AggregateId, ConversationId, EventId, TaskRunId, WorkspaceId},
    task_run::TaskRunEvent,
};
use sha2::{Digest, Sha256};

use super::{submit_fence::submit_task_run, support::*};

fn submit_legacy(database: &Database, tail: u8) -> (TaskRunId, runne_domain::id::CommandId) {
    let conversation_id = ConversationId::from_bytes(command(tail).into_bytes());
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context(tail + 1, "legacy-cancel-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(tail + 1),
                idempotency_key: key("legacy-cancel-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let submit_context = task_context(tail + 2, "legacy-cancel-submit");
    let outcome = database
        .task_runs()
        .submit_task_run_legacy(
            &submit_context,
            LegacySubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunSubmitted {
        taskrun_id,
        new_version: 2,
    } = outcome
    else {
        panic!("public v1 submit returns a version-2 queued TaskRun")
    };
    (taskrun_id, submit_context.command_id)
}

#[test]
fn manual_legacy_taskrun_effects_remain_readable_without_a_v2_submit_receipt() {
    let database = Database::new("legacy-submit-effects-origin");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let (taskrun_id, _) = submit_legacy(&database, 0x48);

    let effects = database
        .store
        .load_task_run_effects(taskrun_id)
        .expect("legacy TaskRun has no v2 origin receipt but remains readable");

    assert_eq!(effects.taskrun_id, taskrun_id);
    assert_eq!(effects.stream_version, 2);
    assert!(effects.local_command.is_none());
    assert_eq!(
        effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Unknown
    );
    assert_eq!(
        effects.successor,
        runne_api::SuccessorEligibilityV1::Blocked
    );
}

#[test]
fn public_v1_submit_cancellation_scans_completes_and_replays_after_reopen() {
    let database = Database::new("legacy-submit-cancellation");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let (taskrun_id, _) = submit_legacy(&database, 0x51);
    database
        .task_runs()
        .cancel_task_run(
            &task_context(0x54, "legacy-cancel-request"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();

    let page = database
        .store
        .scan_pending_taskrun_cancellations(TaskRunQueueScanRequest::new(None, 8).unwrap())
        .unwrap();
    assert_eq!(page.candidates.len(), 1);
    assert_eq!(page.candidates[0].taskrun_id, taskrun_id);
    assert_eq!(page.candidates[0].current_version, 3);

    let completion_context = task_context(0x55, "legacy-cancel-completed");
    let input = CompleteQueuedCancellationInput {
        taskrun_id,
        expected_version: 3,
    };
    let completed = database
        .task_runs()
        .complete_queued_cancellation(&completion_context, input, &database.store)
        .unwrap();
    assert!(matches!(
        completed,
        runne_application::ports::CompleteQueuedCancellationResult::Committed(_)
    ));

    let reopened_store = super::super::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    let reopened_stream = reopened_store.load_task_run(taskrun_id).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"runne-taskrun-queued-cancellation-complete-v1");
    hasher.update(taskrun_id.as_bytes());
    hasher.update(3_u64.to_be_bytes());
    let request = CompleteQueuedCancellationRequest {
        command_id: completion_context.command_id,
        idempotency_key: completion_context.idempotency_key.clone(),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: authority(),
            principal_id: completion_context.principal_id.clone(),
            operation: OperationTag::CompleteQueuedCancellation,
            aggregate_scope: AggregateScope::ExistingTaskRun { taskrun_id },
        },
        command_fingerprint: CommandFingerprint::from_bytes(hasher.finalize().into()),
        expected_version: 3,
        cancellation_completed: UncommittedEvent::from_parts(
            EventId::from_bytes([0x55; 16]),
            AggregateId::TaskRun(taskrun_id),
            AggregateId::TaskRun(taskrun_id),
            reopened_stream.last_event_id,
            completion_context.command_id,
            completion_context.idempotency_key.clone(),
            1,
            completion_context.actor.clone(),
            Sensitivity::Public,
            TaskRunEvent::CancellationCompleted,
        ),
    };
    let duplicate = reopened_store
        .complete_queued_cancellation(request)
        .unwrap();
    assert!(matches!(
        duplicate,
        CompleteQueuedCancellationResult::Duplicate(_)
    ));
    let stream = reopened_stream;
    assert_eq!(stream.current_version, 4);
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(&stream.events)
            .unwrap()
            .state(),
        runne_domain::task_run::TaskRunState::Cancelled
    );
}

#[test]
fn legacy_created_queued_history_without_its_submit_receipt_is_not_cancellable() {
    let database = Database::new("legacy-submit-cancellation-no-receipt");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let (taskrun_id, submit_command) = submit_legacy(&database, 0x61);
    database
        .task_runs()
        .cancel_task_run(
            &task_context(0x64, "legacy-cancel-request-no-receipt"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
    database
        .connection()
        .execute(
            "DELETE FROM command_receipts WHERE command_id=?1",
            [submit_command.as_bytes()],
        )
        .unwrap();

    assert!(
        database
            .task_runs()
            .complete_queued_cancellation(
                &task_context(0x65, "legacy-cancel-no-receipt-completion"),
                CompleteQueuedCancellationInput {
                    taskrun_id,
                    expected_version: 3,
                },
                &database.store,
            )
            .is_err()
    );
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        3
    );
}

#[test]
fn v2_submitted_history_with_an_inconsistent_submit_receipt_is_not_cancellable() {
    let database = Database::new("v2-submit-cancellation-bad-receipt");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submit_task_run(&database, 0x71, "v2-cancel-bad-receipt")
    else {
        panic!("v2 submit outcome expected")
    };
    database
        .task_runs()
        .cancel_task_run(
            &task_context(0x72, "v2-cancel-request-bad-receipt"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
    database
        .connection()
        .execute(
            "UPDATE command_receipts SET fingerprint=zeroblob(32) WHERE command_id=?1",
            [command(0x71).as_bytes()],
        )
        .unwrap();

    assert!(
        database
            .task_runs()
            .complete_queued_cancellation(
                &task_context(0x73, "v2-cancel-completion-bad-receipt"),
                CompleteQueuedCancellationInput {
                    taskrun_id,
                    expected_version: 3,
                },
                &database.store,
            )
            .is_err()
    );
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        3
    );
}

#[path = "queued_cancel_effects.rs"]
mod effects_tests;
