use runne_application::{
    commands::BeginConversationTextInput,
    conversation_text_service::{ConversationTextCommandService, ConversationTextService},
    fingerprint::CommandFingerprint,
    ports::{
        AggregateScope, ConversationRepository, D2ToolLoopFailurePort, D2ToolLoopFailureResult,
        D2ToolLoopFailureV1, EventStore, IdempotencyScope, OperationTag, TextGenerationPhase,
        TextGenerationReceipt,
    },
};
use runne_domain::{
    event::{Sensitivity, UncommittedEvent},
    id::AggregateId,
    message::MessageText,
};
use runne_store::store::D2FailureRecoveryPage;

use super::support::*;

#[test]
fn no_cycle_restart_writer_requires_new_same_node_authority_and_accepts_absent_budget() {
    let fixture = setup::prepare_before_cycle();
    let epoch = register_recovery_epoch(&fixture);
    assert!(
        finish_restart(
            &fixture,
            fixture.assignment.clone(),
            fixture.assignment.node_epoch
        )
        .is_err()
    );
    let mut wrong_fence = fixture.assignment.clone();
    wrong_fence.fence.0 += 1;
    assert!(finish_restart(&fixture, wrong_fence, epoch).is_err());
    let mut wrong_node = fixture.assignment.clone();
    wrong_node.node_id.0 = "02020202020202020202020202020202".into();
    assert!(finish_restart(&fixture, wrong_node, epoch).is_err());
    let accepted = finish_restart(&fixture, fixture.assignment.clone(), epoch);
    assert!(accepted.is_ok(), "valid no-budget restart: {accepted:?}");
}

#[test]
fn no_cycle_restart_writer_rejects_task_scoped_budget_for_another_attempt() {
    let fixture = setup::prepare_before_cycle();
    let epoch = register_recovery_epoch(&fixture);
    let db = fixture.database.connection();
    db.execute(
        "INSERT INTO taskrun_tool_budgets (taskrun_id,attempt_id,fence,node_id,node_epoch,reservation_id,reservation_digest,policy_revision,effects_limit,continuations_limit,effects_used,continuations_used,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'d2-safe-tool-loop-budget-v1',2,2,0,0,1)",
        rusqlite::params![fixture.taskrun_id.as_bytes(), runne_domain::id::AttemptId::from_bytes([0x99; 16]).as_bytes(), fixture.assignment.fence.0 as i64, fixture.assignment.node_id.0.as_str(), fixture.assignment.node_epoch as i64, &[0x98u8; 16][..], &[0x97u8; 32][..]],
    ).unwrap();
    drop(db);
    assert!(finish_restart(&fixture, fixture.assignment.clone(), epoch).is_err());
}

fn register_recovery_epoch(fixture: &setup::Fixture) -> u64 {
    let connection = fixture.database.connection();
    let epoch = runne_store::schema::next_launch_generation(&connection).unwrap();
    runne_store::execution_node::register_local_linux_node(
        &connection,
        *uuid::Uuid::parse_str(&fixture.assignment.node_id.0)
            .unwrap()
            .as_bytes(),
        epoch,
        runne_store::execution_node::LinuxNodeDescriptor { capacity: 1 },
        300,
    )
    .unwrap();
    epoch
}

fn finish_restart(
    fixture: &setup::Fixture,
    assignment: runne_application::ports::TaskRunAssignmentIdentity,
    recovery_epoch: u64,
) -> Result<
    runne_application::ports::TextGenerationReceipt,
    runne_application::conversation_text_service::ConversationTextServiceError,
> {
    finish_restart_at_head(
        fixture,
        assignment,
        recovery_epoch,
        fixture.started.taskrun_version,
    )
}

fn finish_restart_at_head(
    fixture: &setup::Fixture,
    assignment: runne_application::ports::TaskRunAssignmentIdentity,
    recovery_epoch: u64,
    expected_taskrun_head: u64,
) -> Result<
    runne_application::ports::TextGenerationReceipt,
    runne_application::conversation_text_service::ConversationTextServiceError,
> {
    use runne_application::commands::{ConversationTextCompletion, FinishConversationTextInput};
    use runne_application::ports::D2ToolLoopRestartEvidence;
    ConversationTextService::new(
        fixture.store.clone(),
        fixture.store.clone(),
        fixture.runtime_authority.clone(),
        guard(),
    )
    .finish_text(
        &fixture.generation_context,
        FinishConversationTextInput {
            original: fixture.original.clone(),
            started: fixture.started.clone(),
            completion: ConversationTextCompletion::D2ToolLoopRestart {
                evidence: D2ToolLoopRestartEvidence {
                    assignment,
                    recovery_epoch,
                    expected_taskrun_head,
                },
            },
        },
    )
}

#[path = "d2_failure_recovery/restart_reader.rs"]
mod restart_reader;

#[path = "d2_failure_recovery/setup.rs"]
mod setup;

#[test]
fn failed_taskrun_without_projection_is_a_recovery_candidate_until_atomic_settlement() {
    let setup::Fixture {
        database,
        runtime_authority,
        identity,
        store,
        taskrun_id,
        conversation_id,
        assignment,
        original,
        generation_context,
        started,
        cycle_id,
    } = setup::prepare();
    let page: D2FailureRecoveryPage = store.d2_failure_recovery_candidates(None, 8).unwrap();
    assert_eq!(page.candidates.len(), 1);
    let candidate = &page.candidates[0];
    assert_eq!(candidate.taskrun_id, taskrun_id);
    assert_eq!(candidate.attempt_id, assignment.attempt_id);
    assert_eq!(candidate.assignment, assignment);
    assert!(candidate.conversation_id.is_some());
    assert!(candidate.principal_id.is_some());
    let connection = database.connection();
    let settlement_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(settlement_count, 0, "failure projection has not committed");
    drop(connection);

    let failed_stream = store.load_task_run(taskrun_id).unwrap();
    let failed_receipt = TextGenerationReceipt {
        phase: TextGenerationPhase::Rejected,
        conversation_version: started.conversation_version + 1,
        taskrun_version: failed_stream.current_version,
        ..started.clone()
    };
    let conversation = store.load_conversation(conversation_id).unwrap();
    let event_id = runne_domain::id::EventId::from_bytes(command(0xe2).into_bytes());
    let event = UncommittedEvent::from_parts(
        event_id,
        AggregateId::Conversation(conversation_id),
        AggregateId::Conversation(conversation_id),
        conversation.last_event_id,
        generation_context.command_id,
        generation_context.idempotency_key.clone(),
        1,
        generation_context.actor.clone(),
        Sensitivity::Public,
        runne_domain::conversation::ConversationEvent::GenerationFailed {
            taskrun_id,
            attempt_id: assignment.attempt_id,
            reason: runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
        },
    );
    let scope = IdempotencyScope {
        runtime_authority_id: runtime_authority.clone(),
        principal_id: generation_context.principal_id.clone(),
        operation: OperationTag::GenerateConversationText,
        aggregate_scope: AggregateScope::ExistingConversation { conversation_id },
    };
    let fingerprint = CommandFingerprint::for_generate_conversation_text(
        &conversation_id,
        original.expected_version,
        &original.text,
    );
    let failure = D2ToolLoopFailureV1 {
        command_id: generation_context.command_id,
        idempotency_key: generation_context.idempotency_key.clone(),
        idempotency_scope: scope,
        command_fingerprint: fingerprint,
        expected_conversation_version: started.conversation_version,
        expected_taskrun_head: failed_stream.current_version,
        assignment: assignment.clone(),
        taskrun_id,
        attempt_id: assignment.attempt_id,
        cycle_id,
        recovery_epoch: None,
        reason: runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
        actor: generation_context.actor.clone(),
        conversation_id,
        conversation_event: event,
        started_receipt: started.clone(),
        failed_receipt: failed_receipt.clone(),
    };
    let failed = store.fail_d2_tool_loop(failure.clone());
    assert!(
        matches!(failed, Ok(D2ToolLoopFailureResult::Committed { .. })),
        "failure projection: {failed:?}"
    );
    let duplicate = store.fail_d2_tool_loop(failure.clone());
    assert!(
        matches!(&duplicate, Ok(D2ToolLoopFailureResult::Duplicate { .. })),
        "immediate replay: {duplicate:?}"
    );
    let wrong_reason = D2ToolLoopFailureV1 {
        reason: runne_domain::conversation::GenerationFailureReason::ProviderExecutionFailed,
        ..failure.clone()
    };
    assert!(store.fail_d2_tool_loop(wrong_reason).is_err());
    let mut wrong_assignment = failure.clone();
    wrong_assignment.assignment.fence.0 += 1;
    assert!(store.fail_d2_tool_loop(wrong_assignment).is_err());
    let later = ConversationTextService::new(
        store.clone(),
        store.clone(),
        runtime_authority.clone(),
        guard(),
    )
    .begin_text(
        &task_context(0xe3, "d2-failure-later-message"),
        BeginConversationTextInput {
            conversation_id,
            expected_version: failed_receipt.conversation_version,
            text: MessageText::new("later activity").unwrap(),
        },
    )
    .unwrap();
    assert_eq!(later.phase, TextGenerationPhase::Started);
    assert!(matches!(
        store.fail_d2_tool_loop(failure.clone()),
        Ok(D2ToolLoopFailureResult::Duplicate { .. })
    ));
    drop(store);
    drop(database.store);
    let reopened_identity = {
        let connection = rusqlite::Connection::open(database.file.path()).unwrap();
        crate::validated_reopen::read_main_database_identity(&connection).unwrap()
    };
    assert!(
        reopened_identity == identity,
        "the failure projection must preserve the database authority and lineage identity"
    );
    let schema_diagnosis = {
        let connection = rusqlite::Connection::open(database.file.path()).unwrap();
        runne_store::schema::diagnose_schema_matchers(&connection)
    };
    assert_eq!(
        schema_diagnosis,
        runne_store::schema::SchemaMatcherDiagnosis::Accepted,
        "failure projection must preserve an admitted schema"
    );
    crate::validated_reopen::open_validated_connection(database.file.path(), identity)
        .unwrap_or_else(|error| panic!("validated reopen connection: {error:?}"));
    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        identity,
        runtime_authority,
        guard(),
    )
    .unwrap();
    assert!(matches!(
        reopened.fail_d2_tool_loop(failure),
        Ok(D2ToolLoopFailureResult::Duplicate { receipt })
            if receipt.phase == TextGenerationPhase::Rejected
    ));
    let settled = reopened.d2_failure_recovery_candidates(None, 8).unwrap();
    assert!(
        settled.candidates.is_empty(),
        "settled projection is not replayed"
    );
}
