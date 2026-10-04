use super::super::super::append_helpers::*;
use super::super::super::event_context::*;
use super::super::super::event_guard::*;
use super::super::super::parse_helpers::storage_failure;
use super::super::super::position_helpers::*;
use super::super::super::text_receipt_helpers::*;
use super::super::*;
use crate::store::taskrun_submit_origin::RemoteTerminalTaskRunApplicability;
use runne_application::ports::RejectTextGenerationAfterRemoteArtifactCancellationCommit;

#[path = "remote_artifact_receipt.rs"]
mod receipt;
#[path = "remote_artifact_validation.rs"]
mod validation;

use receipt::{
    duplicate_if_exact, insert_closure_receipt, persist_rejected_receipt,
    retire_remote_artifact_cancel_occupation,
};
use validation::{invalid, validate_payload, validate_remote_cancel_source, validate_started};

impl StoreTransaction {
    pub(in crate::store::text) fn reject_text_generation_after_remote_artifact_cancellation_source(
        &self,
        payload: RejectTextGenerationAfterRemoteArtifactCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        validate_payload(&payload)?;
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
            return duplicate_if_exact(&tx, &stored, &payload);
        }
        validate_started(&stored, &payload)?;
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
            || taskrun_head.0 != payload.evidence.cancellation_taskrun_version()
            || payload.conversation_events[0].causation_id().copied() != conversation_head.1
            || payload.taskrun_events[0].causation_id().copied() != taskrun_head.1
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        validate_remote_cancel_source(&tx, &stored, &payload, &self.runtime_authority_id)?;
        let now = current_time_micros()?;
        let latest = conversation_head.2.max(taskrun_head.2);
        if latest.is_some_and(|last| now < last) {
            return Err(CommitError::ClockRegression {
                last_timestamp: Timestamp::from_unix_micros(latest.unwrap_or(now)),
                attempted: Timestamp::from_unix_micros(now),
            });
        }
        let global = next_global_position(&tx)?;
        let next = global
            .checked_add(2)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        guard_conversation_event(
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            global,
            now,
        )?;
        let taskrun_global = global
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        guard_taskrun_event(
            self.prohibited_content.as_ref(),
            &payload.taskrun_events[0],
            payload.receipt.taskrun_version,
            taskrun_global,
            now,
        )?;
        append_conversation_event(
            &tx,
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            global,
            now,
        )?;
        append_taskrun_event(
            &tx,
            self.prohibited_content.as_ref(),
            &payload.taskrun_events[0],
            payload.receipt.taskrun_version,
            taskrun_global,
            now,
        )?;
        // The durable cancellation event sits between claim start and this terminal
        // event, so the generic stream-terminal verifier's version-minus-one lookup
        // is not applicable. The source validator above proves the exact claim and
        // cancellation; this source-specific helper releases that same occupation.
        retire_remote_artifact_cancel_occupation(&tx, &stored, &payload)?;
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
            payload.evidence.cancellation_taskrun_version(),
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
        update_global_position(&tx, next)?;
        insert_closure_receipt(&tx, &stored, &payload, conversation_head.1, now)?;
        persist_rejected_receipt(&tx, &payload, &scope, now)?;
        tx.commit()
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        Ok(TextGenerationCommitResult::Committed {
            result: payload.receipt,
        })
    }
}
