use super::super::*;
use crate::codec::TextGenerationReceiptCodec;
use runne_application::ports::{
    D2ToolLoopCompletionPort, D2ToolLoopCompletionResult, D2ToolLoopCompletionV1,
    D2ToolTerminalSourceV1,
};
use runne_domain::{agent_loop::LoopDisposition, task_run::TaskRun};
use sha2::{Digest, Sha256};

mod failure;
mod helpers;
mod replay;
use helpers::*;

impl D2ToolLoopCompletionPort for StoreTransaction {
    fn complete_d2_tool_loop(
        &self,
        input: D2ToolLoopCompletionV1,
    ) -> Result<D2ToolLoopCompletionResult, CommitError> {
        complete_d2_tool_loop_impl(self, input)
    }
}

impl StoreTransaction {}

fn complete_d2_tool_loop_impl(
    store: &StoreTransaction,
    input: D2ToolLoopCompletionV1,
) -> Result<D2ToolLoopCompletionResult, CommitError> {
    use crate::store::parse_helpers::storage_failure;
    if input.taskrun_id != input.assignment.taskrun_id
        || input.attempt_id != input.assignment.attempt_id
        || input.started_receipt.taskrun_id != input.taskrun_id
        || input.started_receipt.attempt_id != input.attempt_id
        || input.started_receipt.conversation_id != input.conversation_id
        || input.started_receipt.phase != TextGenerationPhase::Started
        || input.completed_receipt.phase != TextGenerationPhase::Completed
        || input.completed_receipt.taskrun_id != input.taskrun_id
        || input.completed_receipt.attempt_id != input.attempt_id
        || input.completed_receipt.conversation_id != input.conversation_id
        || input.completed_receipt.workspace_id != input.started_receipt.workspace_id
        || input.completed_receipt.user_message_id != input.started_receipt.user_message_id
        || input.completed_receipt.assistant_message_id
            != input.started_receipt.assistant_message_id
        || input
            .expected_conversation_version
            .checked_add(1)
            .is_none_or(|version| input.completed_receipt.conversation_version != version)
        || input.completed_receipt.taskrun_version != input.expected_taskrun_head
        || input.evaluation_ref.taskrun_id != input.taskrun_id
        || input.evaluation_ref.evaluated_stream_head >= input.expected_taskrun_head
        || input.terminal_attempt_id == [0; 16]
        || input.terminal_outbox_id == [0; 16]
        || input.settlement_digest == IntegrityDigest::from_bytes([0; 32])
        || input.terminal_sources.is_empty()
        || input.terminal_sources.len() > 32
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let (message_id, text_digest, text_length) = match input.conversation_event.payload() {
        ConversationEvent::AssistantMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            text,
        } if *taskrun_id == input.taskrun_id && *attempt_id == input.attempt_id => (
            *message_id,
            IntegrityDigest::from_bytes(Sha256::digest(text.as_str().as_bytes()).into()),
            text.as_str().len() as u64,
        ),
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    };
    if message_id != input.completed_receipt.assistant_message_id
        || text_digest != input.assistant_text_digest
        || text_length != input.assistant_text_length
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }

    let mut writer = store
        .inner
        .writer
        .lock()
        .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
    let tx = writer
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
    let now = super::super::position_helpers::current_time_micros()?;
    if input.idempotency_scope.runtime_authority_id != *store.runtime_authority_id()
        || input.idempotency_scope.operation != OperationTag::GenerateConversationText
        || input.idempotency_scope.aggregate_scope
            != (AggregateScope::ExistingConversation {
                conversation_id: input.conversation_id,
            })
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let scope = IdempotencyScopeCodec
        .encode(&input.idempotency_scope)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let stored = super::super::text_receipt_helpers::lookup_text_receipt(
        &tx,
        input.command_id,
        &input.idempotency_key,
        &scope,
        &input.command_fingerprint,
        &store.runtime_authority_id,
    )?;
    let TextGenerationReceiptLookup::Duplicate { stored_result } = stored else {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    };
    if stored_result == input.completed_receipt {
        let completion = completion_row(&tx, input.command_id)?;
        let digest = receipt_digest(&input.completed_receipt)?;
        if let Some(row) = completion.as_ref()
            && row.completed_replay_matches(&tx, &input, message_id, digest)?
        {
            return Ok(D2ToolLoopCompletionResult::Duplicate {
                receipt: stored_result,
            });
        }
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if stored_result != input.started_receipt {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }

    let conversation_head = super::super::position_helpers::load_stream_head_for_commit(
        &tx,
        CORRELATION_TYPE_CONVERSATION,
        input.conversation_id.as_bytes(),
    )?;
    let taskrun_stream = crate::store::taskrun_claim::stream_validate::verify_stream(
        &tx,
        input.taskrun_id,
        Some(input.expected_taskrun_head),
    )
    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if conversation_head.0 != input.expected_conversation_version
        || input.started_receipt.conversation_version != conversation_head.0
        || taskrun_stream.version != input.expected_taskrun_head
        || input.conversation_event.causation_id().copied() != conversation_head.1
        || input.conversation_event.aggregate_id()
            != &AggregateId::Conversation(input.conversation_id)
    {
        return Err(CommitError::VersionConflict {
            expected: input.expected_conversation_version,
            actual: conversation_head.0,
        });
    }
    let task = TaskRun::replay(&taskrun_stream.events)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if task.state() != TaskRunState::Succeeded {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let terminal_event = taskrun_stream
        .events
        .last()
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let terminal_event_id = *terminal_event.event_id();
    let terminal_version = taskrun_stream.version;
    let cycle_complete = taskrun_stream.events.iter().any(|event| matches!(event.payload(),
        TaskRunEvent::LoopCycleCompleted { cycle_id, attempt_id, disposition: LoopDisposition::Complete { plan_evaluation_ref } }
            if *cycle_id == input.cycle_id && *attempt_id == input.attempt_id && plan_evaluation_ref == &input.evaluation_ref));
    if !cycle_complete
        || !matches!(
            terminal_event.payload(),
            TaskRunEvent::TaskRunCompleted {
                result: runne_domain::command::TerminalResult::Success
            }
        )
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }

    validate_terminal_outbox(&tx, &input)?;
    crate::store::taskrun_claim::verify_assignment_history(&tx, &input.assignment)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    retire_d2_occupation(&tx, &input, terminal_event_id, terminal_version)?;

    let global = super::super::position_helpers::next_global_position(&tx)?;
    let _ = crate::store::event_guard::guard_conversation_event(
        store.prohibited_content.as_ref(),
        &input.conversation_event,
        input.completed_receipt.conversation_version,
        global,
        now,
    )?;
    super::super::append_helpers::append_conversation_event(
        &tx,
        store.prohibited_content.as_ref(),
        &input.conversation_event,
        input.completed_receipt.conversation_version,
        global,
        now,
    )?;
    super::super::position_helpers::update_stream_head(
        &tx,
        CORRELATION_TYPE_CONVERSATION,
        input.conversation_id.as_bytes(),
        input.expected_conversation_version,
        input.completed_receipt.conversation_version,
        message_event_id(&input.conversation_event),
        now,
    )?;
    crate::store::snapshot::refresh_aggregate_snapshot(
        &tx,
        CORRELATION_TYPE_CONVERSATION,
        input.conversation_id.as_bytes(),
    )?;

    let encoded = TextGenerationReceiptCodec
        .encode(&input.completed_receipt)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let receipt_digest = IntegrityDigest::from_bytes(Sha256::digest(&encoded).into());
    write_completion_linkage(&tx, &input, message_id, receipt_digest, now)?;
    let changed = tx.execute("UPDATE command_receipts SET command_outcome=?1,committed_at=?2 WHERE command_id=?3 AND idempotency_scope_bytes=?4 AND idempotency_key=?5 AND fingerprint=?6",
        params![encoded, now, input.command_id.as_bytes(), scope, input.idempotency_key.as_str().as_bytes(), input.command_fingerprint.as_bytes()])
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if changed != 1 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let updated_outbox = tx.execute("UPDATE provider_terminal_outbox SET state=2,receipt_digest=?1,applied_at=?2 WHERE outbox_id=?3 AND state=1 AND receipt_digest IS NULL",
        params![receipt_digest.as_bytes(), now / 1_000, input.terminal_outbox_id.as_slice()])
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if updated_outbox != 1 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let changed = tx.execute("UPDATE provider_dispatch_attempts SET state=5 WHERE attempt_id=?1 AND state=4 AND settlement_digest=?2",
        params![input.terminal_attempt_id.as_slice(), input.settlement_digest.as_bytes()])
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if changed != 1 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    super::super::position_helpers::update_global_position(
        &tx,
        global
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?,
    )?;
    tx.commit()
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(D2ToolLoopCompletionResult::Committed {
        receipt: input.completed_receipt,
    })
}
