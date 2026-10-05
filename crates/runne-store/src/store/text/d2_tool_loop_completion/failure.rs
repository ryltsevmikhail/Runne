use super::super::*;
use crate::codec::TextGenerationReceiptCodec;
use runne_application::ports::{
    D2ToolLoopCancellationEvidence, D2ToolLoopFailureResult, D2ToolLoopFailureV1,
    TaskRunAssignmentIdentity,
};
use runne_domain::{agent_loop::LoopDisposition, task_run::TaskRun};
mod occupation;
mod tool_rows;
use occupation::{retire_occupation, verify_released_occupation};
use tool_rows::{verify_budget_assignment_if_present, verify_safe_tool_stop};
mod safe_stop;
mod validate;

fn fail_d2_tool_loop(
    store: &StoreTransaction,
    input: D2ToolLoopFailureV1,
) -> Result<D2ToolLoopFailureResult, CommitError> {
    use crate::store::parse_helpers::storage_failure;
    use crate::store::test_support_diagnostics as diagnostics;
    validate::validate_input(store, &input)?;
    let scope = IdempotencyScopeCodec
        .encode(&input.idempotency_scope)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let mut writer = store
        .inner
        .writer
        .lock()
        .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
    let tx = writer
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
    if input.reason == runne_domain::conversation::GenerationFailureReason::InterruptedByRestart
        && input.recovery_epoch.is_none()
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if let Some(epoch) = input.recovery_epoch {
        let node = uuid::Uuid::parse_str(&input.assignment.node_id.0)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let authority = uuid::Uuid::parse_str(&store.runtime_authority_id.0)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let now_ms = super::super::position_helpers::current_time_micros()?
            .checked_div(1_000)
            .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let live: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM execution_nodes WHERE node_id=?1 AND launch_generation=?2 AND expires_at_ms>?3)",
            params![node.as_bytes(), i64::try_from(epoch).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?, now_ms],
            |row| row.get(0),
        ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if authority != node || epoch <= input.assignment.node_epoch || !live {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    }
    let stored = diagnostics::on_error(
        "failure.receipt_lookup",
        super::super::text_receipt_helpers::lookup_text_receipt(
            &tx,
            input.command_id,
            &input.idempotency_key,
            &scope,
            &input.command_fingerprint,
            &store.runtime_authority_id,
        ),
    )?;
    let run = crate::store::taskrun_claim::stream_validate::verify_stream(
        &tx,
        input.taskrun_id,
        Some(input.expected_taskrun_head),
    )
    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let task = TaskRun::replay(&run.events)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let invocation_count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3",
        params![input.taskrun_id.as_bytes(), input.attempt_id.as_bytes(), input.cycle_id.as_bytes()],
        |row| row.get(0),
    ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let expected_reason = if input.reason
        == runne_domain::conversation::GenerationFailureReason::InterruptedByRestart
    {
        "interrupted_by_restart"
    } else if invocation_count == 0 {
        "provider_execution_rejected"
    } else {
        "D2 tool approval or effect did not complete safely"
    };
    let exact_failure = task.state() == TaskRunState::Failed
        && run.events.last().is_some_and(|event| matches!(event.payload(),
            TaskRunEvent::TaskRunFailed { reason } if reason == expected_reason))
        && run.events.iter().any(|event| matches!(event.payload(),
            TaskRunEvent::LoopCycleCompleted { cycle_id, attempt_id, disposition: LoopDisposition::Fail { reason, .. } }
            if *cycle_id == input.cycle_id
                && *attempt_id == input.attempt_id
                && reason == expected_reason));
    if !exact_failure {
        diagnostics::record("failure.canonical_taskrun");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    crate::store::taskrun_claim::verify_assignment_history(&tx, &input.assignment)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    verify_budget_assignment_if_present(
        &tx,
        input.taskrun_id,
        input.attempt_id,
        &input.assignment,
    )?;
    let node = uuid::Uuid::parse_str(&input.assignment.node_id.0)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    diagnostics::on_error(
        "failure.provider_round_chain",
        crate::store::verify_d2_cancelled_provider_rounds(
            &tx,
            input.taskrun_id,
            input.attempt_id,
            runne_application::ports::D2ToolLoopCancellationEvidence {
                node_id: *node.as_bytes(),
                node_epoch: input.assignment.node_epoch,
                fence: input.assignment.fence.0,
                cancellation_taskrun_version: input.expected_taskrun_head,
            },
            input.started_receipt.taskrun_version,
            input.expected_taskrun_head,
        ),
    )?;
    let terminal_event = run
        .events
        .last()
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let terminal_event_id = *terminal_event.event_id();
    diagnostics::on_error(
        "failure.safe_local_stop",
        verify_safe_tool_stop(
            &tx,
            input.taskrun_id,
            input.attempt_id,
            input.cycle_id,
            &input.assignment,
            input.reason
                == runne_domain::conversation::GenerationFailureReason::InterruptedByRestart
                && invocation_count > 0,
        ),
    )?;
    match stored {
        TextGenerationReceiptLookup::Duplicate { stored_result }
            if stored_result == input.failed_receipt =>
        {
            let conversation = crate::store::conversation::load_conversation_from_connection(
                &tx,
                input.conversation_id,
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
            let expected_sequence = input
                .started_receipt
                .conversation_version
                .checked_add(1)
                .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
            let previous_id = usize::try_from(expected_sequence)
                .ok()
                .and_then(|sequence| sequence.checked_sub(2))
                .and_then(|index| conversation.events.get(index))
                .map(|event| *event.event_id());
            let event = usize::try_from(expected_sequence)
                .ok()
                .and_then(|sequence| sequence.checked_sub(1))
                .and_then(|index| conversation.events.get(index))
                .is_some_and(|saved| {
                    saved.event_id() == input.conversation_event.event_id()
                        && saved.sequence() == expected_sequence
                        && saved.payload() == input.conversation_event.payload()
                        && saved.command_id() == &input.command_id
                        && saved.idempotency_key() == &input.idempotency_key
                        && saved.actor() == &input.actor
                        && saved.sensitivity() == input.conversation_event.sensitivity()
                        && saved.causation_id().copied() == previous_id
                });
            diagnostics::on_error(
                "failure.duplicate_occupation",
                verify_released_occupation(&tx, &input, terminal_event_id),
            )?;
            if event && conversation.current_version >= stored_result.conversation_version {
                tx.commit()
                    .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
                return Ok(D2ToolLoopFailureResult::Duplicate {
                    receipt: stored_result,
                });
            }
            diagnostics::record("failure.duplicate_conversation_event");
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        TextGenerationReceiptLookup::Duplicate { stored_result }
            if stored_result == input.started_receipt => {}
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    }
    let conversation_head = super::super::position_helpers::load_stream_head_for_commit(
        &tx,
        CORRELATION_TYPE_CONVERSATION,
        input.conversation_id.as_bytes(),
    )?;
    if conversation_head.0 != input.expected_conversation_version
        || input.started_receipt.conversation_version != conversation_head.0
        || input.conversation_event.causation_id().copied() != conversation_head.1
        || input.conversation_event.aggregate_id()
            != &AggregateId::Conversation(input.conversation_id)
    {
        return Err(CommitError::VersionConflict {
            expected: input.expected_conversation_version,
            actual: conversation_head.0,
        });
    }
    retire_occupation(&tx, &input, terminal_event_id, input.expected_taskrun_head)?;
    let now = super::super::position_helpers::current_time_micros()?;
    let global = super::super::position_helpers::next_global_position(&tx)?;
    crate::store::event_guard::guard_conversation_event(
        store.prohibited_content.as_ref(),
        &input.conversation_event,
        input.failed_receipt.conversation_version,
        global,
        now,
    )?;
    super::super::append_helpers::append_conversation_event(
        &tx,
        store.prohibited_content.as_ref(),
        &input.conversation_event,
        input.failed_receipt.conversation_version,
        global,
        now,
    )?;
    super::super::position_helpers::update_stream_head(
        &tx,
        CORRELATION_TYPE_CONVERSATION,
        input.conversation_id.as_bytes(),
        input.expected_conversation_version,
        input.failed_receipt.conversation_version,
        *input.conversation_event.event_id(),
        now,
    )?;
    super::super::position_helpers::update_global_position(
        &tx,
        global
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?,
    )?;
    crate::store::snapshot::refresh_aggregate_snapshot(
        &tx,
        CORRELATION_TYPE_CONVERSATION,
        input.conversation_id.as_bytes(),
    )?;
    let encoded = TextGenerationReceiptCodec
        .encode(&input.failed_receipt)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let changed = tx.execute(
        "UPDATE command_receipts SET command_outcome=?1,committed_at=?2 WHERE command_id=?3 AND idempotency_scope_bytes=?4 AND idempotency_key=?5 AND fingerprint=?6",
        params![encoded, now, input.command_id.as_bytes(), scope, input.idempotency_key.as_str().as_bytes(), input.command_fingerprint.as_bytes()],
    ).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if changed != 1 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    tx.commit()
        .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
    Ok(D2ToolLoopFailureResult::Committed {
        receipt: input.failed_receipt,
    })
}
