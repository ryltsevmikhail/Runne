use super::*;
use runne_application::commands::{
    BeginConversationTextInput, CancelTaskRunInput, ConversationTextCompletion,
    FinishConversationTextInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{EventStore, ProjectWorkspaceRepository};
use runne_domain::id::{ConversationId, WorkspaceId};
use runne_domain::message::MessageText;

#[path = "no_admission/support.rs"]
mod support;
use support::*;

#[path = "no_admission/namespace_control.rs"]
mod namespace_control;
#[path = "no_admission/proof_kind.rs"]
mod proof_kind;

#[test]
fn fresh_issue_accepts_exact_started_principal_before_cancel() {
    let fixture = running("no-admission-live-start", 0x41);
    let counts: (i64, i64, i64, i64) = fixture
        .database
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_execution_admissions WHERE taskrun_id=?1 AND execution_attempt_id=?2),
                    (SELECT COUNT(*) FROM provider_budget_reservations WHERE provider_idempotency_key LIKE 'unknown-successor-effect-%'),
                    (SELECT COUNT(*) FROM provider_remote_request_intents WHERE taskrun_id=?1 AND taskrun_attempt_id=?2),
                    (SELECT COUNT(*) FROM provider_execution_admissions WHERE taskrun_id=?1
                       AND execution_attempt_id=?2 AND dispatch_attempt_id<>execution_attempt_id)",
            rusqlite::params![fixture.taskrun_id.as_bytes(), fixture.claim_identity.attempt_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 2, 1, 1));
}

#[test]
fn fresh_issue_rejects_a_different_conversation_origin() {
    let fixture = running_without_provider_admission("no-admission-wrong-origin", 0x42);
    let begin_context = context(0x44, "unknown-successor-generation");
    let started = fixture
        .database
        .store
        .load_text_generation_receipt_by_command(
            begin_context.command_id,
            &begin_context.idempotency_key,
        )
        .unwrap();
    let mut request = fresh_issue_request(&started, "principal-1");
    request.conversation_id = ConversationId::from_bytes([0xe4; 16]);
    let dispatch = crate::validated_reopen::open_provider_dispatch(
        fixture.database.file.path(),
        fixture.database.identity,
    )
    .unwrap();
    dispatch
        .persist_prepared(
            &fixture.launch,
            &runne_store::provider::PreparedProviderRecord {
                call_id: request.prepared.call_id,
                call_digest_version: request.prepared.call_digest_version,
                prepared_digest: request.prepared.prepared_digest,
                render_digest: request.prepared.render_digest,
                profile_digest: request.prepared.profile_digest,
            },
        )
        .unwrap();
    assert!(matches!(
        fixture.execution.issue(&fixture.launch, &request),
        Err(runne_application::provider::ProviderAdmissionError::AuthorityDenied)
    ));
    assert_no_provider_effects(&fixture.database, started.taskrun_id, started.attempt_id);
}

#[test]
fn claimed_no_admission_cancel_closes_and_replays_after_reopen() {
    let fixture = running_without_provider_admission("no-admission-claimed", 0x51);
    let begin_context = context(0x53, "unknown-successor-generation");
    let started = fixture
        .database
        .store
        .load_text_generation_receipt_by_command(
            begin_context.command_id,
            &begin_context.idempotency_key,
        )
        .unwrap();
    assert_fresh_issue_denied(
        &fixture.database,
        &fixture.execution,
        &fixture.launch,
        &started,
        "principal-2",
    );
    assert_no_provider_effects(&fixture.database, started.taskrun_id, started.attempt_id);
    let cancellation_version = request_cancel(&fixture.database, &started);
    assert_fresh_issue_denied(
        &fixture.database,
        &fixture.execution,
        &fixture.launch,
        &started,
        "principal-1",
    );
    close_cancelled_without_admission(
        &fixture.database,
        begin_context.clone(),
        started.clone(),
        "successor fixture request",
        cancellation_version,
    );
    assert_no_provider_effects(&fixture.database, started.taskrun_id, started.attempt_id);

    let reopened = crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        super::super::fixture::runtime_authority(),
        guard(),
    )
    .unwrap();
    let reopened_text = ConversationTextService::new(
        reopened.clone(),
        reopened.clone(),
        super::super::fixture::runtime_authority(),
        guard(),
    );
    let replay = reopened_text
        .finish_text(
            &begin_context,
            FinishConversationTextInput {
                original: BeginConversationTextInput {
                    conversation_id: started.conversation_id,
                    expected_version: started.conversation_version - 1,
                    text: MessageText::new("successor fixture request").unwrap(),
                },
                started: started.clone(),
                completion: ConversationTextCompletion::NoProviderAdmissionCancellation {
                    evidence: runne_application::ports::ProviderNoAdmissionCancellationEvidence {
                        cancellation_taskrun_version: started.taskrun_version + 1,
                    },
                },
            },
        )
        .unwrap();
    assert_eq!(
        replay.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(
            &reopened.load_task_run(started.taskrun_id).unwrap().events
        )
        .unwrap()
        .state(),
        runne_domain::task_run::TaskRunState::Cancelled
    );
    assert_no_assistant_output(&reopened, started.conversation_id);
}

#[test]
fn direct_no_admission_cancel_closes_with_exact_legacy_origin() {
    let runtime_authority = super::super::fixture::runtime_authority();
    let database = Database::new_with_database_authority(
        "no-admission-direct",
        runtime_authority.clone(),
        [1; 16],
    );
    let repository = database.repository();
    repository
        .create_project(
            "principal-1",
            command(1),
            &key("direct-project"),
            project(PROJECT, "Direct"),
        )
        .unwrap();
    repository
        .create_workspace(
            "principal-1",
            command(2),
            &key("direct-workspace"),
            workspace(WORKSPACE, PROJECT, "Direct workspace"),
        )
        .unwrap();
    let conversation_id = ConversationId::from_bytes(command(0x61).into_bytes());
    ConversationService::new(
        database.store.clone(),
        database.store.clone(),
        runtime_authority.clone(),
    )
    .create_from_application(
        &context(0x62, "direct-conversation"),
        runne_api::CreateConversationInput {
            conversation_id,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            command_id: command(0x62),
            idempotency_key: key("direct-conversation"),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let begin_context = context(0x63, "direct-text-begin");
    let text = ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        runtime_authority.clone(),
        guard(),
    );
    let started = text
        .begin(
            &begin_context,
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("direct request").unwrap(),
            },
        )
        .unwrap();
    let (execution, launch) = super::super::fixture::dispatch::runtime_launch(&database);
    let cancellation_version = request_cancel(&database, &started);
    assert_fresh_issue_denied(&database, &execution, &launch, &started, "principal-1");
    close_cancelled_without_admission(
        &database,
        begin_context.clone(),
        started.clone(),
        "direct request",
        cancellation_version,
    );
    assert_no_provider_effects(&database, started.taskrun_id, started.attempt_id);

    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        runtime_authority.clone(),
        guard(),
    )
    .unwrap();
    let reopened_text = ConversationTextService::new(
        reopened.clone(),
        reopened.clone(),
        runtime_authority,
        guard(),
    );
    let replay = reopened_text
        .finish_text(
            &begin_context,
            FinishConversationTextInput {
                original: BeginConversationTextInput {
                    conversation_id: started.conversation_id,
                    expected_version: started.conversation_version - 1,
                    text: MessageText::new("direct request").unwrap(),
                },
                started: started.clone(),
                completion: ConversationTextCompletion::NoProviderAdmissionCancellation {
                    evidence: runne_application::ports::ProviderNoAdmissionCancellationEvidence {
                        cancellation_taskrun_version: started.taskrun_version + 1,
                    },
                },
            },
        )
        .unwrap();
    assert_eq!(
        replay.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    assert_no_assistant_output(&reopened, started.conversation_id);
    let duplicate = reopened_text
        .finish_text(
            &begin_context,
            FinishConversationTextInput {
                original: BeginConversationTextInput {
                    conversation_id: started.conversation_id,
                    expected_version: started.conversation_version - 1,
                    text: MessageText::new("direct request").unwrap(),
                },
                started: started.clone(),
                completion: ConversationTextCompletion::NoProviderAdmissionCancellation {
                    evidence: runne_application::ports::ProviderNoAdmissionCancellationEvidence {
                        cancellation_taskrun_version: started.taskrun_version + 1,
                    },
                },
            },
        )
        .unwrap();
    assert_eq!(duplicate, replay);
}
