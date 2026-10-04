use super::*;
use runne_api::CreateConversationInput;
use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, ConversationTextCompletion,
    FinishConversationTextInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{TaskRunNoEffectScanRequest, TaskRunNoEffectScanner};
use runne_domain::id::{ConversationId, WorkspaceId};
use runne_domain::message::MessageText;

fn conversation_id(database: &Database, taskrun_id: runne_domain::id::TaskRunId) -> ConversationId {
    match database.store.load_task_run(taskrun_id).unwrap().events[0].payload() {
        TaskRunEvent::TaskRunSubmitted {
            conversation_id, ..
        } => *conversation_id,
        _ => panic!("submitted TaskRun event expected"),
    }
}

fn assignment_for(
    database: &Database,
    taskrun_id: runne_domain::id::TaskRunId,
    tail: u8,
) -> (TaskRunAssignmentIdentity, u64, String, u64) {
    let (node, epoch) = node_registration(database);
    let (identity, version) = claim(database, taskrun_id, tail, &node, epoch);
    (identity, version, node, epoch)
}

#[test]
fn restart_preserves_started_generation_for_interrupted_settlement() {
    let database = Database::new("taskrun-no-effect-begun-restart");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x41, "begun-before-restart");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!()
    };
    let conversation_id = conversation_id(&database, taskrun_id);
    let (identity, version, _node, old_epoch) = assignment_for(&database, taskrun_id, 0x42);
    let service = ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        authority(),
        guard(),
    );
    let context = task_context(0x43, "begin-before-restart");
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("test prompt").unwrap(),
    };
    let started = service
        .begin_claimed_text(
            &context,
            BeginClaimedConversationTextInput {
                original: original.clone(),
                taskrun_id,
                attempt_id: identity.attempt_id,
                taskrun_version: version,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                assignment: identity.clone(),
            },
        )
        .unwrap();
    let release = release_request(&database, identity.clone(), version, 0x44);
    let reopened_store = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    let page = reopened_store
        .scan_no_effect_assignments(
            TaskRunNoEffectScanRequest::new(None, 8, identity.node_id.clone(), old_epoch + 1)
                .unwrap(),
        )
        .unwrap();
    assert!(page.candidates.is_empty());
    assert_eq!(
        reopened_store.release_taskrun_no_effect(release),
        Err(TaskRunNoEffectReleaseError::DispatchMayHaveStarted)
    );

    let reopened_service = ConversationTextService::new(
        reopened_store.clone(),
        reopened_store.clone(),
        authority(),
        guard(),
    );
    reopened_service
        .finish_text(
            &context,
            FinishConversationTextInput {
                original,
                started,
                completion: ConversationTextCompletion::Rejected {
                    reason:
                        runne_domain::conversation::GenerationFailureReason::InterruptedByRestart,
                },
            },
        )
        .unwrap();
    let stream = reopened_store.load_task_run(taskrun_id).unwrap();
    assert!(matches!(
        stream.events.last().unwrap().payload(),
        TaskRunEvent::TaskRunFailed { reason } if reason == "interrupted_by_restart"
    ));
    let phase = reopened_store
        .load_text_generation_receipt_by_command(context.command_id, &context.idempotency_key)
        .unwrap()
        .phase;
    assert_eq!(
        phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    let state: String = database
        .connection()
        .query_row(
            "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "released");
}

#[test]
fn restart_scanner_fails_closed_on_tampered_submit_receipt_without_settling() {
    let database = Database::new("taskrun-started-corrupt-submit-receipt");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x48, "started-corrupt-submit");
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome
    else {
        panic!("submitted TaskRun")
    };
    let conversation_id = conversation_id(&database, taskrun_id);
    let (identity, version, _, _) = assignment_for(&database, taskrun_id, 0x49);
    let service = ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        authority(),
        guard(),
    );
    let context = task_context(0x4a, "start-before-origin-tamper");
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("test prompt").unwrap(),
    };
    service
        .begin_claimed_text(
            &context,
            BeginClaimedConversationTextInput {
                original,
                taskrun_id,
                attempt_id: identity.attempt_id,
                taskrun_version: version,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                assignment: identity.clone(),
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

    let connection = database.connection();
    assert!(
        runne_store::orphan_settlement::scan_provably_effect_free_started_generations(
            &connection,
            &authority(),
        )
        .is_err()
    );
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        version
    );
    let occupation: String = connection
        .query_row(
            "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(occupation, "active");
}

#[test]
fn restart_releases_old_claim_when_no_generation_began() {
    let database = Database::new("taskrun-no-effect-unbegun-restart");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x51, "unbegun-before-restart");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!()
    };
    let (identity, version, _node, old_epoch) = assignment_for(&database, taskrun_id, 0x52);
    let release = release_request(&database, identity.clone(), version, 0x53);
    let reopened_store = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    let page = reopened_store
        .scan_no_effect_assignments(
            TaskRunNoEffectScanRequest::new(None, 8, identity.node_id.clone(), old_epoch + 1)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(page.candidates.len(), 1);
    assert_eq!(page.candidates[0].identity, identity);
    reopened_store.release_taskrun_no_effect(release).unwrap();
    assert!(matches!(
        runne_domain::task_run::TaskRun::replay(
            &reopened_store.load_task_run(taskrun_id).unwrap().events
        )
        .unwrap()
        .state(),
        runne_domain::task_run::TaskRunState::Failed
    ));
}

#[test]
fn orphan_scan_preserves_direct_generated_text_origin() {
    let database = Database::new("taskrun-no-effect-direct-text-origin");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0x61).into_bytes());
    let creation = task_context(0x62, "direct-text-conversation");
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &creation,
            CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: creation.command_id,
                idempotency_key: creation.idempotency_key.clone(),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let text = ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        authority(),
        guard(),
    );
    let context = task_context(0x63, "direct-generated-text");
    let started = text
        .begin(
            &context,
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("legacy direct text").unwrap(),
            },
        )
        .unwrap();
    let connection = database.connection();
    let candidates = runne_store::orphan_settlement::scan_provably_effect_free_started_generations(
        &connection,
        &authority(),
    )
    .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].receipt.taskrun_id, started.taskrun_id);
    assert!(matches!(
        database
            .store
            .load_task_run(started.taskrun_id)
            .unwrap()
            .events[0]
            .payload(),
        TaskRunEvent::TaskRunCreated
    ));
}
