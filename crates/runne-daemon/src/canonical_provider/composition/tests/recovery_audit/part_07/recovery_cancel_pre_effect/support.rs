use super::super::super::fixture::Harness;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    AggregateScope, ApplicationCommandContext, ConversationRepository, EventStore, IdGenerator,
    IdempotencyScope, OperationTag, PrincipalId, RuntimeAuthorityId, TextGenerationPhase,
};
use runne_domain::event::{CommandContext, materialize_batch};
use runne_domain::id::MessageId;
use runne_domain::task_run::TaskRun;
use runne_domain::{command::TaskRunCommand, conversation::Conversation};

#[derive(Clone, Copy)]
pub(super) enum Mutation {
    AssistantId,
    Workspace,
    Authority,
    Fingerprint,
    Principal,
    DispatchId,
    CancellationVersion,
}

pub(super) fn direct_cancellation_payload(
    store: &runne_store::store::StoreTransaction,
    context: &ApplicationCommandContext,
    started: &runne_application::ports::TextGenerationReceipt,
    cancellation_version: u64,
    authority: [u8; 16],
    mutation: Option<Mutation>,
) -> runne_application::ports::RejectTextGenerationAfterPreEffectCancellationCommit {
    let conversation_stream = store.load_conversation(started.conversation_id).unwrap();
    let conversation = Conversation::replay(&conversation_stream.events).unwrap();
    let taskrun_stream = store.load_task_run(started.taskrun_id).unwrap();
    let taskrun = TaskRun::replay(&taskrun_stream.events).unwrap();
    let conversation_drafts = conversation
        .decide(runne_domain::command::ConversationCommand::FailGeneration {
            taskrun_id: started.taskrun_id,
            attempt_id: started.attempt_id,
            reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
        })
        .unwrap();
    let taskrun_drafts = taskrun
        .decide(TaskRunCommand::CompleteCancellation)
        .unwrap();
    let mut ids = store.next_event_ids(2).unwrap().into_iter();
    let conversation_id = ids.next().unwrap();
    let taskrun_id = ids.next().unwrap();
    let domain_context = CommandContext {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key.clone(),
        actor: context.actor.clone(),
    };
    let conversation_events = materialize_batch(
        conversation_drafts,
        &[conversation_id],
        conversation_stream.last_event_id,
        &domain_context,
    )
    .unwrap();
    let taskrun_events = materialize_batch(
        taskrun_drafts,
        &[taskrun_id],
        taskrun_stream.last_event_id,
        &domain_context,
    )
    .unwrap();
    let mut receipt = started.clone();
    receipt.phase = TextGenerationPhase::Rejected;
    receipt.conversation_version += 1;
    receipt.taskrun_version = cancellation_version + 1;
    let mut scope_authority = RuntimeAuthorityId(hex::encode(authority));
    let mut principal_id = context.principal_id.clone();
    let mut fingerprint = CommandFingerprint::for_generate_conversation_text(
        &started.conversation_id,
        started.conversation_version - 1,
        &match conversation_stream.events.last().unwrap().payload() {
            runne_domain::conversation::ConversationEvent::UserMessageAppended { text, .. } => {
                text.clone()
            }
            _ => unreachable!(),
        },
    );
    match mutation {
        None => {}
        Some(Mutation::AssistantId) => {
            receipt.assistant_message_id = MessageId::from_bytes([0xa5; 16]);
        }
        Some(Mutation::Workspace) => {
            receipt.workspace_id = "018f2e3a-7000-7000-8000-000000000199".parse().unwrap();
        }
        Some(Mutation::Authority) => {
            scope_authority = RuntimeAuthorityId("018f2e3a700070008000000000000199".into());
        }
        Some(Mutation::Fingerprint) => fingerprint = CommandFingerprint::from_bytes([0x55; 32]),
        Some(Mutation::Principal) => principal_id = PrincipalId("wrong-principal".into()),
        Some(Mutation::DispatchId | Mutation::CancellationVersion) => {}
    }
    let candidate_dispatch = store
        .provider_rejection_recovery_candidates(None, 128)
        .unwrap()
        .candidates
        .into_iter()
        .find(|candidate| candidate.taskrun_id == started.taskrun_id)
        .unwrap()
        .dispatch_attempt_id;
    let evidence_dispatch = if matches!(mutation, Some(Mutation::DispatchId)) {
        [0x77; 16]
    } else {
        candidate_dispatch
    };
    let proof_cancellation_version = if matches!(mutation, Some(Mutation::CancellationVersion)) {
        cancellation_version + 1
    } else {
        cancellation_version
    };
    runne_application::ports::RejectTextGenerationAfterPreEffectCancellationCommit {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key.clone(),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: scope_authority,
            principal_id,
            operation: OperationTag::GenerateConversationText,
            aggregate_scope: AggregateScope::ExistingConversation {
                conversation_id: started.conversation_id,
            },
        },
        command_fingerprint: fingerprint,
        expected_conversation_version: started.conversation_version,
        expected_started_taskrun_version: started.taskrun_version,
        evidence: runne_application::ports::ProviderPreEffectCancellationEvidence {
            dispatch_attempt_id: evidence_dispatch,
            cancellation_taskrun_version: proof_cancellation_version,
        },
        conversation_events,
        taskrun_events,
        receipt,
    }
}

pub(super) fn cancellation_state(
    harness: &Harness,
    taskrun_id: runne_domain::id::TaskRunId,
    conversation_id: runne_domain::id::ConversationId,
) -> (i64, i64, i64, String) {
    let connection = harness.query_connection();
    cancellation_state_on(&connection, taskrun_id, conversation_id)
}

pub(super) fn cancellation_state_on(
    connection: &rusqlite::Connection,
    taskrun_id: runne_domain::id::TaskRunId,
    conversation_id: runne_domain::id::ConversationId,
) -> (i64, i64, i64, String) {
    connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM events WHERE aggregate_type=1 AND aggregate_id=?1),
                (SELECT COUNT(*) FROM events WHERE aggregate_type=2 AND aggregate_id=?2),
                (SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1),
                (SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1)",
            rusqlite::params![taskrun_id.as_bytes(), conversation_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

pub(super) fn assert_cancelled_state(
    harness: &Harness,
    taskrun_id: runne_domain::id::TaskRunId,
    conversation_id: runne_domain::id::ConversationId,
    context: &ApplicationCommandContext,
    expected_taskrun_version: u64,
) {
    let taskrun = harness.store.load_task_run(taskrun_id).unwrap();
    assert_eq!(
        TaskRun::replay(&taskrun.events).unwrap().state(),
        runne_domain::task_run::TaskRunState::Cancelled
    );
    let conversation = harness.store.load_conversation(conversation_id).unwrap();
    assert!(conversation.events.iter().any(|event| matches!(
        event.payload(),
        runne_domain::conversation::ConversationEvent::GenerationFailed {
            taskrun_id: id, reason: runne_domain::conversation::GenerationFailureReason::Cancelled, ..
        } if *id == taskrun_id
    )));
    assert!(!conversation.events.iter().any(|event| matches!(
        event.payload(),
        runne_domain::conversation::ConversationEvent::AssistantMessageAppended { taskrun_id: id, .. }
            if *id == taskrun_id
    )));
    let receipt = harness
        .store
        .load_text_generation_receipt_by_command(context.command_id, &context.idempotency_key)
        .unwrap();
    assert_eq!(receipt.phase, TextGenerationPhase::Rejected);
    assert_eq!(receipt.taskrun_version, expected_taskrun_version + 1);
    let connection = harness.query_connection();
    let row: (i64, i64, String, i64, i64) = connection.query_row(
        "SELECT d.state,d.pre_effect_rejection,o.state,
                (SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts r WHERE r.taskrun_id=a.taskrun_id),
                (SELECT COUNT(*) FROM provider_effect_starts e WHERE e.dispatch_attempt_id=d.attempt_id)
         FROM provider_dispatch_attempts d JOIN provider_execution_admissions a ON a.dispatch_attempt_id=d.attempt_id
         JOIN taskrun_assignment_occupations o ON o.taskrun_id=a.taskrun_id WHERE a.taskrun_id=?1",
        [taskrun_id.as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).unwrap();
    assert_eq!(row, (2, 7, "released".into(), 1, 0));
    for table in [
        "provider_stream_journal",
        "provider_terminal_outbox",
        "provider_accounting_settlements",
    ] {
        let count: i64 = connection.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE dispatch_attempt_id=(SELECT dispatch_attempt_id FROM provider_execution_admissions WHERE taskrun_id=?1)"),
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 0, "unexpected row in {table}");
    }
}

mod negative;
mod replay;
pub(super) use negative::{
    assert_binding_mismatch_is_rejected, assert_revoked_authority_is_rejected,
    assert_uncertain_dispatch_is_rejected, assert_unexpected_intent_is_rejected,
};
pub(super) use replay::{ReplayPlan, verify_replay_after_corruption_and_advance};
