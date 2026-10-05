use super::super::append_helpers::*;
use super::super::event_guard::*;
use super::super::parse_helpers::*;
use super::super::position_helpers::*;
use super::super::test_support_diagnostics as diagnostics;
use super::super::text_receipt_helpers::*;
use super::super::text_validation_helpers::*;
use super::super::*;
use runne_application::ports::D2ToolLoopRestartEvidence;
mod api;
mod append;
impl StoreTransaction {
    pub(super) fn reject_text_generation_inner(
        &self,
        payload: RejectTextGenerationCommit,
        d2_restart: Option<D2ToolLoopRestartEvidence>,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        diagnostics::on_error(
            "reject.payload_validation",
            validate_reject_text_payload(&payload, &self.runtime_authority_id, d2_restart.as_ref()),
        )?;
        let mut connection = self.inner.writer.lock().map_err(|_| {
            diagnostics::record("reject.writer_lock");
            storage_failure(StorageFailureKind::Unavailable)
        })?;
        let transaction = diagnostics::on_error(
            "reject.begin_transaction",
            connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|_| storage_failure(StorageFailureKind::Unavailable)),
        )?;
        let scope = IdempotencyScopeCodec
            .encode(&payload.idempotency_scope)
            .map_err(|_| {
                diagnostics::record("reject.scope_encode");
                storage_failure(StorageFailureKind::IntegrityViolation)
            })?;
        let stored = match diagnostics::on_error(
            "reject.receipt_lookup",
            lookup_text_receipt(
                &transaction,
                payload.command_id,
                &payload.idempotency_key,
                &scope,
                &payload.command_fingerprint,
                &self.runtime_authority_id,
            ),
        )? {
            TextGenerationReceiptLookup::Miss => {
                diagnostics::record("reject.receipt_miss");
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
        let terminal_taskrun_head =
            append::terminal_taskrun_head(stored.taskrun_version, d2_restart.as_ref());
        let expected_rejected = TextGenerationReceipt {
            phase: payload.receipt.phase,
            conversation_version: stored.conversation_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: stored.conversation_version,
                    event_count: 1,
                },
            )?,
            taskrun_version: terminal_taskrun_head.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: terminal_taskrun_head,
                    event_count: 1,
                },
            )?,
            ..stored.clone()
        };
        if stored.phase != TextGenerationPhase::Started
            || stored.conversation_version != payload.expected_conversation_version
            || stored.taskrun_version != payload.expected_taskrun_version
            || payload.receipt != expected_rejected
        {
            diagnostics::record("reject.receipt_shape");
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }

        let conversation_head = diagnostics::on_error(
            "reject.conversation_head",
            load_stream_head_for_commit(
                &transaction,
                CORRELATION_TYPE_CONVERSATION,
                stored.conversation_id.as_bytes(),
            ),
        )?;
        let taskrun_head = diagnostics::on_error(
            "reject.taskrun_head",
            load_stream_head_for_commit(
                &transaction,
                CORRELATION_TYPE_TASK_RUN,
                stored.taskrun_id.as_bytes(),
            ),
        )?;
        if conversation_head.0 != payload.expected_conversation_version {
            diagnostics::record("reject.conversation_version");
            return Err(CommitError::VersionConflict {
                expected: payload.expected_conversation_version,
                actual: conversation_head.0,
            });
        }
        let expected_taskrun_head = d2_restart
            .as_ref()
            .map_or(payload.expected_taskrun_version, |evidence| {
                evidence.expected_taskrun_head
            });
        if taskrun_head.0 != expected_taskrun_head {
            diagnostics::record("reject.taskrun_version");
            return Err(CommitError::VersionConflict {
                expected: expected_taskrun_head,
                actual: taskrun_head.0,
            });
        }
        if let Some(evidence) = d2_restart.as_ref() {
            diagnostics::on_error(
                "reject.d2_restart_safe_stop",
                crate::store::text::d2_tool_loop_restart::verify(
                    &transaction,
                    &payload,
                    evidence.clone(),
                    &stored,
                ),
            )?;
        }
        diagnostics::on_error(
            "reject.remote_source_guard",
            super::remote_artifact_reject_guard::validate_non_output_rejection(
                &transaction,
                &stored,
                &payload,
                &self.runtime_authority_id,
            ),
        )?;
        if payload.conversation_events[0].causation_id().copied() != conversation_head.1
            || payload.taskrun_events[0].causation_id().copied() != taskrun_head.1
        {
            diagnostics::record("reject.causation");
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let now = diagnostics::on_error("reject.clock", current_time_micros())?;
        let latest_timestamp = conversation_head.2.max(taskrun_head.2);
        if latest_timestamp.is_some_and(|last| now < last) {
            diagnostics::record("reject.clock_regression");
            return Err(CommitError::ClockRegression {
                last_timestamp: Timestamp::from_unix_micros(latest_timestamp.unwrap_or(now)),
                attempted: Timestamp::from_unix_micros(now),
            });
        }
        let global_position =
            diagnostics::on_error("reject.global_position", next_global_position(&transaction))?;
        let next_global_position = global_position.checked_add(2).ok_or_else(|| {
            diagnostics::record("reject.global_position_exhausted");
            CommitError::GlobalPositionExhausted
        })?;
        diagnostics::on_error(
            "reject.conversation_guard",
            guard_conversation_event(
                self.prohibited_content.as_ref(),
                &payload.conversation_events[0],
                payload.receipt.conversation_version,
                global_position,
                now,
            ),
        )?;
        let taskrun_global_position = global_position.checked_add(1).ok_or_else(|| {
            diagnostics::record("reject.global_position_exhausted");
            CommitError::GlobalPositionExhausted
        })?;
        diagnostics::on_error(
            "reject.taskrun_guard",
            guard_taskrun_event(
                self.prohibited_content.as_ref(),
                &payload.taskrun_events[0],
                payload.receipt.taskrun_version,
                taskrun_global_position,
                now,
            ),
        )?;
        diagnostics::on_error(
            "reject.occupation_check",
            super::terminal_occupation::verify_claimed_terminal_before_append(
                &transaction,
                &payload.receipt,
                payload.expected_taskrun_version,
                &payload.taskrun_events[0],
            ),
        )?;
        append::append_events_and_retire(
            &transaction,
            self.prohibited_content.as_ref(),
            &payload,
            d2_restart.as_ref(),
            global_position,
            taskrun_global_position,
            now,
        )?;
        diagnostics::on_error(
            "reject.conversation_head_update",
            update_stream_head(
                &transaction,
                CORRELATION_TYPE_CONVERSATION,
                stored.conversation_id.as_bytes(),
                payload.expected_conversation_version,
                payload.receipt.conversation_version,
                *payload.conversation_events[0].event_id(),
                now,
            ),
        )?;
        diagnostics::on_error(
            "reject.taskrun_head_update",
            update_stream_head(
                &transaction,
                CORRELATION_TYPE_TASK_RUN,
                stored.taskrun_id.as_bytes(),
                expected_taskrun_head,
                payload.receipt.taskrun_version,
                *payload.taskrun_events[0].event_id(),
                now,
            ),
        )?;
        diagnostics::on_error(
            "reject.application_receipt",
            super::remote_artifact_reject_guard::record_non_output_application(
                &transaction,
                &stored,
                &payload,
            ),
        )?;
        diagnostics::on_error(
            "reject.conversation_snapshot",
            crate::store::snapshot::refresh_aggregate_snapshot(
                &transaction,
                CORRELATION_TYPE_CONVERSATION,
                stored.conversation_id.as_bytes(),
            ),
        )?;
        diagnostics::on_error(
            "reject.taskrun_snapshot",
            crate::store::snapshot::refresh_aggregate_snapshot(
                &transaction,
                CORRELATION_TYPE_TASK_RUN,
                stored.taskrun_id.as_bytes(),
            ),
        )?;
        diagnostics::on_error(
            "reject.global_position_update",
            update_global_position(&transaction, next_global_position),
        )?;
        let outcome = TextGenerationReceiptCodec
            .encode(&payload.receipt)
            .map_err(|_| {
                diagnostics::record("reject.outcome_encode");
                storage_failure(StorageFailureKind::IntegrityViolation)
            })?;
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
            .map_err(|_| {
                diagnostics::record("reject.receipt_update");
                storage_failure(StorageFailureKind::IntegrityViolation)
            })?;
        if updated != 1 {
            diagnostics::record("reject.receipt_update_count");
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        transaction.commit().map_err(|_| {
            diagnostics::record("reject.commit");
            storage_failure(StorageFailureKind::IntegrityViolation)
        })?;
        Ok(TextGenerationCommitResult::Committed {
            result: payload.receipt,
        })
    }
}
