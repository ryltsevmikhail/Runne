use super::super::append_helpers::*;
use super::super::event_context::*;
use super::super::event_guard::*;
use super::super::parse_helpers::*;
use super::super::position_helpers::*;
use super::super::test_support_diagnostics as diagnostics;
use super::super::text_receipt_helpers::*;
use super::super::*;
use runne_application::ports::{
    ProviderCancellationProof, RejectTextGenerationAfterCancellationCommit,
};

mod api;
mod disposition;
mod duplicate;
mod remote_artifact;

impl StoreTransaction {
    fn reject_text_generation_after_cancellation_impl(
        &self,
        payload: RejectTextGenerationAfterCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        let (
            cancellation_taskrun_version,
            dispatch_attempt_id,
            terminal_evidence,
            unknown_evidence,
        ) = match payload.proof {
            ProviderCancellationProof::Terminal(evidence) => (
                evidence.cancellation_taskrun_version,
                Some(evidence.dispatch_attempt_id),
                Some(evidence),
                None,
            ),
            ProviderCancellationProof::UnknownTerminal(evidence) => (
                evidence.cancellation_taskrun_version,
                Some(evidence.dispatch_attempt_id),
                None,
                Some(evidence),
            ),
            ProviderCancellationProof::PreEffect(evidence) => (
                evidence.cancellation_taskrun_version,
                Some(evidence.dispatch_attempt_id),
                None,
                None,
            ),
            ProviderCancellationProof::NoAdmission(evidence) => {
                (evidence.cancellation_taskrun_version, None, None, None)
            }
        };
        if payload.conversation_events.len() != 1
            || payload.taskrun_events.len() != 1
            || terminal_evidence.is_some_and(|evidence| {
                evidence.disposition
                    == runne_provider::ProviderTerminalDisposition::CancelledUncertain
            })
            || cancellation_taskrun_version
                != payload
                    .expected_started_taskrun_version
                    .checked_add(1)
                    .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?
            || payload.receipt.phase != TextGenerationPhase::Rejected
            || payload.receipt.conversation_version
                != payload
                    .expected_conversation_version
                    .checked_add(1)
                    .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?
            || payload.receipt.taskrun_version
                != cancellation_taskrun_version
                    .checked_add(1)
                    .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?
            || !matches!(payload.conversation_events[0].payload(),
                ConversationEvent::GenerationFailed { taskrun_id, attempt_id, reason }
                    if *taskrun_id == payload.receipt.taskrun_id
                        && *attempt_id == payload.receipt.attempt_id
                        && *reason == runne_domain::conversation::GenerationFailureReason::Cancelled)
            || payload.taskrun_events[0].payload() != &TaskRunEvent::CancellationCompleted
            || !valid_event_context(
                &payload.conversation_events[0],
                payload.command_id,
                &payload.idempotency_key,
                AggregateId::Conversation(payload.receipt.conversation_id),
                Sensitivity::Public,
            )
            || !valid_event_context(
                &payload.taskrun_events[0],
                payload.command_id,
                &payload.idempotency_key,
                AggregateId::TaskRun(payload.receipt.taskrun_id),
                Sensitivity::Public,
            )
        {
            if matches!(payload.proof, ProviderCancellationProof::NoAdmission(_)) {
                diagnostics::record("cancel.no_admission.payload_shape");
            }
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let scope = IdempotencyScopeCodec
            .encode(&payload.idempotency_scope)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let stored = match lookup_text_receipt(
            &tx,
            payload.command_id,
            &payload.idempotency_key,
            &scope,
            &payload.command_fingerprint,
            &self.runtime_authority_id,
        )? {
            TextGenerationReceiptLookup::Miss => {
                return Err(storage_failure(StorageFailureKind::IntegrityViolation));
            }
            TextGenerationReceiptLookup::Duplicate { stored_result } => stored_result,
        };
        if stored.phase == TextGenerationPhase::Rejected {
            super::super::terminal_cancellation_receipt::validate_terminal_cancellation_receipt(
                &tx, &stored,
            )?;
            let exact = duplicate::validate(
                &tx,
                &stored,
                &payload,
                terminal_evidence,
                dispatch_attempt_id,
                unknown_evidence,
            )?;
            if exact && stored == payload.receipt {
                return Ok(TextGenerationCommitResult::Duplicate {
                    stored_result: stored,
                });
            }
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        if stored.phase != TextGenerationPhase::Started
            || stored.conversation_id != payload.receipt.conversation_id
            || stored.taskrun_id != payload.receipt.taskrun_id
            || stored.attempt_id != payload.receipt.attempt_id
            || stored.conversation_version != payload.expected_conversation_version
            || stored.taskrun_version != payload.expected_started_taskrun_version
            || payload.receipt.conversation_id != stored.conversation_id
            || payload.receipt.workspace_id != stored.workspace_id
            || payload.receipt.taskrun_id != stored.taskrun_id
            || payload.receipt.attempt_id != stored.attempt_id
            || payload.receipt.user_message_id != stored.user_message_id
            || payload.receipt.assistant_message_id != stored.assistant_message_id
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let conversation_head = load_stream_head_for_commit(
            &tx,
            CORRELATION_TYPE_CONVERSATION,
            stored.conversation_id.as_bytes(),
        )?;
        let taskrun_head = load_stream_head_for_commit(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            stored.taskrun_id.as_bytes(),
        )?;
        if conversation_head.0 != payload.expected_conversation_version
            || taskrun_head.0 != cancellation_taskrun_version
            || payload.conversation_events[0].causation_id().copied() != conversation_head.1
            || payload.taskrun_events[0].causation_id().copied() != taskrun_head.1
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        crate::conversation_writer_lease::ensure_writer_lease(
            &tx,
            stored.conversation_id.as_bytes(),
            payload.idempotency_scope.principal_id.0.as_str(),
            crate::conversation_writer_lease::unix_now(),
        )
        .map_err(|_| storage_failure(StorageFailureKind::WriterFenced))?;
        diagnostics::on_error(
            "cancel.verify_evidence",
            super::terminal_cancellation_validation::verify_cancellation_evidence(
                &tx,
                &payload,
                &self.runtime_authority_id,
            ),
        )?;
        let now = current_time_micros()?;
        let latest = conversation_head.2.max(taskrun_head.2);
        if latest.is_some_and(|last| now < last) {
            return Err(CommitError::ClockRegression {
                last_timestamp: Timestamp::from_unix_micros(latest.unwrap_or(now)),
                attempted: Timestamp::from_unix_micros(now),
            });
        }
        let position = next_global_position(&tx)?;
        let next_position = position
            .checked_add(2)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        guard_conversation_event(
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            position,
            now,
        )?;
        let taskrun_position = position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        guard_taskrun_event(
            self.prohibited_content.as_ref(),
            &payload.taskrun_events[0],
            payload.receipt.taskrun_version,
            taskrun_position,
            now,
        )?;
        append_conversation_event(
            &tx,
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            position,
            now,
        )?;
        append_taskrun_event(
            &tx,
            self.prohibited_content.as_ref(),
            &payload.taskrun_events[0],
            payload.receipt.taskrun_version,
            taskrun_position,
            now,
        )?;
        super::terminal_cancellation_validation::retire_cancellation_occupation(&tx, &payload)?;
        update_stream_head(
            &tx,
            CORRELATION_TYPE_CONVERSATION,
            stored.conversation_id.as_bytes(),
            payload.expected_conversation_version,
            payload.receipt.conversation_version,
            *payload.conversation_events[0].event_id(),
            now,
        )?;
        update_stream_head(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            stored.taskrun_id.as_bytes(),
            cancellation_taskrun_version,
            payload.receipt.taskrun_version,
            *payload.taskrun_events[0].event_id(),
            now,
        )?;
        crate::store::snapshot::refresh_aggregate_snapshot(
            &tx,
            CORRELATION_TYPE_CONVERSATION,
            stored.conversation_id.as_bytes(),
        )?;
        crate::store::snapshot::refresh_aggregate_snapshot(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            stored.taskrun_id.as_bytes(),
        )?;
        update_global_position(&tx, next_position)?;
        let bytes = TextGenerationReceiptCodec
            .encode(&payload.receipt)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        if tx.execute("UPDATE command_receipts SET command_outcome=?1,committed_at=?2 WHERE command_id=?3 AND idempotency_scope_bytes=?4 AND idempotency_key=?5 AND fingerprint=?6",
            params![bytes, now, payload.command_id.as_bytes(), scope, payload.idempotency_key.as_str().as_bytes(), payload.command_fingerprint.as_bytes()]).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))? != 1 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        tx.commit()
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        Ok(TextGenerationCommitResult::Committed {
            result: payload.receipt,
        })
    }
}
