use super::super::super::super::fixture::Harness;
use super::cancellation_state;
use super::cancellation_state_on;
use runne_application::ports::{
    ApplicationCommandContext, ConversationTextRepository,
    RejectTextGenerationAfterPreEffectCancellationCommit,
};

pub(crate) fn assert_revoked_authority_is_rejected(
    harness: &Harness,
    taskrun_id: runne_domain::id::TaskRunId,
    conversation_id: runne_domain::id::ConversationId,
    context: &ApplicationCommandContext,
    payload: &runne_application::ports::RejectTextGenerationAfterPreEffectCancellationCommit,
) {
    let before = cancellation_state(harness, taskrun_id, conversation_id);
    let receipt_before = harness
        .store
        .load_text_generation_receipt_by_command(context.command_id, &context.idempotency_key)
        .unwrap();
    let writer = harness.writer_connection();
    let active: i64 = writer
        .query_row(
            "SELECT active FROM provider_runtime_authority_state WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active, 1);
    writer
        .execute(
            "UPDATE provider_runtime_authority_state SET active=0 WHERE id=1",
            [],
        )
        .unwrap();
    assert!(
        harness
            .store
            .reject_text_generation_after_pre_effect_cancellation(payload.clone())
            .is_err()
    );
    writer
        .execute(
            "UPDATE provider_runtime_authority_state SET active=1 WHERE id=1",
            [],
        )
        .unwrap();
    assert_eq!(
        cancellation_state_on(&writer, taskrun_id, conversation_id),
        before
    );
    assert_eq!(
        harness
            .store
            .load_text_generation_receipt_by_command(context.command_id, &context.idempotency_key)
            .unwrap(),
        receipt_before
    );
}

pub(crate) fn assert_binding_mismatch_is_rejected(
    harness: &Harness,
    taskrun_id: runne_domain::id::TaskRunId,
    conversation_id: runne_domain::id::ConversationId,
    context: &ApplicationCommandContext,
    payload: &RejectTextGenerationAfterPreEffectCancellationCommit,
) {
    let snapshot = mutation_snapshot(harness, taskrun_id, conversation_id, context);
    let writer = harness.writer_connection();
    let original: Vec<u8> = writer
        .query_row(
            "SELECT profile_digest FROM taskrun_provider_bindings WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    writer
        .execute_batch("DROP TRIGGER taskrun_provider_bindings_immutable;")
        .unwrap();
    writer
        .execute(
            "UPDATE taskrun_provider_bindings SET profile_digest=zeroblob(32) WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    reject_without_mutation(harness, &writer, snapshot, payload);
    writer
        .execute(
            "UPDATE taskrun_provider_bindings SET profile_digest=?1 WHERE taskrun_id=?2",
            rusqlite::params![original, taskrun_id.as_bytes()],
        )
        .unwrap();
    writer
        .execute_batch("CREATE TRIGGER taskrun_provider_bindings_immutable BEFORE UPDATE ON taskrun_provider_bindings BEGIN SELECT RAISE(ABORT,'TaskRun provider binding is append only'); END;")
        .unwrap();
}

pub(crate) fn assert_unexpected_intent_is_rejected(
    harness: &Harness,
    taskrun_id: runne_domain::id::TaskRunId,
    conversation_id: runne_domain::id::ConversationId,
    context: &ApplicationCommandContext,
    payload: &RejectTextGenerationAfterPreEffectCancellationCommit,
) {
    let snapshot = mutation_snapshot(harness, taskrun_id, conversation_id, context);
    let writer = harness.writer_connection();
    writer
        .execute(
            "INSERT INTO taskrun_dispatch_intents(taskrun_id,fence,attempt_id,node_id,node_epoch,state)
             SELECT taskrun_id,fence,attempt_id,node_id,node_epoch,'unknown'
             FROM taskrun_assignment_occupations WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    reject_without_mutation(harness, &writer, snapshot, payload);
    writer
        .execute_batch("DROP TRIGGER taskrun_dispatch_intents_no_delete;")
        .unwrap();
    writer
        .execute(
            "DELETE FROM taskrun_dispatch_intents WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    writer
        .execute_batch("CREATE TRIGGER taskrun_dispatch_intents_no_delete BEFORE DELETE ON taskrun_dispatch_intents BEGIN SELECT RAISE(ABORT,'dispatch intent is append only'); END;")
        .unwrap();
}

pub(crate) fn assert_uncertain_dispatch_is_rejected(
    harness: &Harness,
    taskrun_id: runne_domain::id::TaskRunId,
    conversation_id: runne_domain::id::ConversationId,
    context: &ApplicationCommandContext,
    payload: &RejectTextGenerationAfterPreEffectCancellationCommit,
) {
    let snapshot = mutation_snapshot(harness, taskrun_id, conversation_id, context);
    let writer = harness.writer_connection();
    writer
        .execute(
            "UPDATE provider_dispatch_attempts SET state=6,pre_effect_rejection=NULL WHERE attempt_id=?1",
            [payload.evidence.dispatch_attempt_id.as_slice()],
        )
        .unwrap();
    reject_without_mutation(harness, &writer, snapshot, payload);
    writer
        .execute(
            "UPDATE provider_dispatch_attempts SET state=2,pre_effect_rejection=7 WHERE attempt_id=?1",
            [payload.evidence.dispatch_attempt_id.as_slice()],
        )
        .unwrap();
}

struct MutationSnapshot<'a> {
    taskrun_id: runne_domain::id::TaskRunId,
    conversation_id: runne_domain::id::ConversationId,
    context: &'a ApplicationCommandContext,
    state: (i64, i64, i64, String),
    receipt: runne_application::ports::TextGenerationReceipt,
}

fn reject_without_mutation(
    harness: &Harness,
    connection: &rusqlite::Connection,
    snapshot: MutationSnapshot<'_>,
    payload: &RejectTextGenerationAfterPreEffectCancellationCommit,
) {
    assert!(
        harness
            .store
            .reject_text_generation_after_pre_effect_cancellation(payload.clone())
            .is_err()
    );
    assert_eq!(
        cancellation_state_on(connection, snapshot.taskrun_id, snapshot.conversation_id),
        snapshot.state
    );
    assert_eq!(
        harness
            .store
            .load_text_generation_receipt_by_command(
                snapshot.context.command_id,
                &snapshot.context.idempotency_key,
            )
            .unwrap(),
        snapshot.receipt
    );
}

fn mutation_snapshot<'a>(
    harness: &Harness,
    taskrun_id: runne_domain::id::TaskRunId,
    conversation_id: runne_domain::id::ConversationId,
    context: &'a ApplicationCommandContext,
) -> MutationSnapshot<'a> {
    MutationSnapshot {
        taskrun_id,
        conversation_id,
        context,
        state: cancellation_state(harness, taskrun_id, conversation_id),
        receipt: harness
            .store
            .load_text_generation_receipt_by_command(context.command_id, &context.idempotency_key)
            .unwrap(),
    }
}
