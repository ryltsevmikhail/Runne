use super::super::append_helpers::*;
use super::super::event_guard::*;
use super::super::parse_helpers::*;
use super::super::position_helpers::*;
use super::super::text_receipt_helpers::*;
use super::super::text_validation_helpers::*;
use super::super::*;

impl StoreTransaction {
    pub(super) fn finish_text_generation_impl(
        &self,
        payload: FinishTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        validate_finish_text_payload(&payload, &self.runtime_authority_id)?;
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let scope = IdempotencyScopeCodec
            .encode(&payload.idempotency_scope)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let stored = match lookup_text_receipt(
            &transaction,
            payload.command_id,
            &payload.idempotency_key,
            &scope,
            &payload.command_fingerprint,
        )? {
            TextGenerationReceiptLookup::Miss => {
                return Err(storage_failure(StorageFailureKind::IntegrityViolation));
            }
            TextGenerationReceiptLookup::Duplicate { stored_result } => stored_result,
        };
        if matches!(
            stored.phase,
            TextGenerationPhase::Completed
                | TextGenerationPhase::Rejected
                | TextGenerationPhase::ProhibitedInputRejected
        ) {
            return Ok(TextGenerationCommitResult::Duplicate {
                stored_result: stored,
            });
        }
        let expected_completed = TextGenerationReceipt {
            phase: TextGenerationPhase::Completed,
            conversation_version: stored.conversation_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: stored.conversation_version,
                    event_count: 1,
                },
            )?,
            taskrun_version: stored.taskrun_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: stored.taskrun_version,
                    event_count: 1,
                },
            )?,
            ..stored.clone()
        };
        if stored.phase != TextGenerationPhase::Started
            || stored.conversation_version != payload.expected_conversation_version
            || stored.taskrun_version != payload.expected_taskrun_version
            || payload.receipt != expected_completed
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }

        let conversation_head = load_stream_head_for_commit(
            &transaction,
            CORRELATION_TYPE_CONVERSATION,
            stored.conversation_id.as_bytes(),
        )?;
        let taskrun_head = load_stream_head_for_commit(
            &transaction,
            CORRELATION_TYPE_TASK_RUN,
            stored.taskrun_id.as_bytes(),
        )?;
        if conversation_head.0 != payload.expected_conversation_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_conversation_version,
                actual: conversation_head.0,
            });
        }
        if taskrun_head.0 != payload.expected_taskrun_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_taskrun_version,
                actual: taskrun_head.0,
            });
        }
        if payload.conversation_events[0].causation_id().copied() != conversation_head.1
            || payload.taskrun_events[0].causation_id().copied() != taskrun_head.1
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let now = current_time_micros()?;
        let latest_timestamp = conversation_head.2.max(taskrun_head.2);
        if latest_timestamp.is_some_and(|last| now < last) {
            return Err(CommitError::ClockRegression {
                last_timestamp: Timestamp::from_unix_micros(latest_timestamp.unwrap_or(now)),
                attempted: Timestamp::from_unix_micros(now),
            });
        }
        let global_position = next_global_position(&transaction)?;
        let next_global_position = global_position
            .checked_add(2)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let _ = guard_conversation_event(
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            global_position,
            now,
        )?;
        let taskrun_global_position = global_position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let _ = guard_taskrun_event(
            self.prohibited_content.as_ref(),
            &payload.taskrun_events[0],
            payload.receipt.taskrun_version,
            taskrun_global_position,
            now,
        )?;
        append_conversation_event(
            &transaction,
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            global_position,
            now,
        )?;
        append_taskrun_event(
            &transaction,
            self.prohibited_content.as_ref(),
            &payload.taskrun_events[0],
            payload.receipt.taskrun_version,
            taskrun_global_position,
            now,
        )?;
        update_stream_head(
            &transaction,
            CORRELATION_TYPE_CONVERSATION,
            stored.conversation_id.as_bytes(),
            payload.expected_conversation_version,
            payload.receipt.conversation_version,
            *payload.conversation_events[0].event_id(),
            now,
        )?;
        update_stream_head(
            &transaction,
            CORRELATION_TYPE_TASK_RUN,
            stored.taskrun_id.as_bytes(),
            payload.expected_taskrun_version,
            payload.receipt.taskrun_version,
            *payload.taskrun_events[0].event_id(),
            now,
        )?;
        crate::store::snapshot::refresh_aggregate_snapshot(
            &transaction,
            CORRELATION_TYPE_CONVERSATION,
            stored.conversation_id.as_bytes(),
        )?;
        crate::store::snapshot::refresh_aggregate_snapshot(
            &transaction,
            CORRELATION_TYPE_TASK_RUN,
            stored.taskrun_id.as_bytes(),
        )?;
        update_global_position(&transaction, next_global_position)?;
        let outcome = TextGenerationReceiptCodec
            .encode(&payload.receipt)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let updated = transaction
            .execute(
                "UPDATE command_receipts
                 SET command_outcome = ?1, committed_at = ?2
                 WHERE command_id = ?3 AND idempotency_scope_bytes = ?4
                   AND idempotency_key = ?5 AND fingerprint = ?6",
                params![
                    outcome,
                    now,
                    payload.command_id.as_bytes(),
                    scope,
                    payload.idempotency_key.as_str().as_bytes(),
                    payload.command_fingerprint.as_bytes(),
                ],
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        if updated != 1 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        transaction
            .commit()
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        Ok(TextGenerationCommitResult::Committed {
            result: payload.receipt,
        })
    }
}
