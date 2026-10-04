use super::super::append_helpers::*;
use super::super::event_guard::*;
use super::super::parse_helpers::*;
use super::super::position_helpers::*;
use super::super::text_receipt_helpers::*;
use super::super::*;
use super::claimed_begin_receipt::persist_claimed_text_receipt;
use super::claimed_begin_validation::{
    validate_claimed_text_payload, verify_claimed_taskrun, verify_immutable_claim_identity,
};

impl StoreTransaction {
    pub(super) fn begin_claimed_text_generation_impl(
        &self,
        payload: BeginClaimedTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        validate_claimed_text_payload(&payload, &self.runtime_authority_id)?;
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
        if let TextGenerationReceiptLookup::Duplicate { stored_result } = lookup_text_receipt(
            &tx,
            payload.command_id,
            &payload.idempotency_key,
            &scope,
            &payload.command_fingerprint,
            &self.runtime_authority_id,
        )? {
            verify_immutable_claim_identity(
                &tx,
                &payload.assignment,
                payload.receipt.taskrun_version,
            )?;
            if stored_result.taskrun_id != payload.receipt.taskrun_id
                || stored_result.attempt_id != payload.receipt.attempt_id
                || stored_result.workspace_id != payload.receipt.workspace_id
            {
                return Err(storage_failure(StorageFailureKind::IntegrityViolation));
            }
            return Ok(TextGenerationCommitResult::Duplicate { stored_result });
        }
        let conversation_id = payload.receipt.conversation_id;
        crate::conversation_writer_lease::ensure_writer_lease(
            &tx,
            conversation_id.as_bytes(),
            payload.idempotency_scope.principal_id.0.as_str(),
            unix_now(),
        )
        .map_err(|error| match error {
            crate::conversation_writer_lease::WriterLeaseError::FencedByOtherWriter => {
                storage_failure(StorageFailureKind::WriterFenced)
            }
            _ => storage_failure(StorageFailureKind::Unavailable),
        })?;
        verify_claimed_taskrun(&tx, &payload, &self.runtime_authority_id)?;
        let (version, last_event, last_timestamp) = tx.query_row(
            "SELECT current_version,last_event_id,last_timestamp FROM aggregate_streams WHERE aggregate_type=?1 AND aggregate_id=?2",
            params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?, row.get::<_, Option<i64>>(2)?)),
        ).optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
            .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let version =
            u64::try_from(version).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if version != payload.expected_conversation_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_conversation_version,
                actual: version,
            });
        }
        let last_event = last_event.map(parse_event_id_for_commit).transpose()?;
        if payload.conversation_events[0].causation_id().copied() != last_event {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let workspace_payload: Vec<u8> = tx.query_row(
            "SELECT payload FROM events WHERE aggregate_type=?1 AND aggregate_id=?2 AND sequence=1",
            params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()], |row| row.get(0),
        ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if !matches!(ConversationEventCodec.decode(&workspace_payload),
            Ok(ConversationEvent::ConversationCreated { workspace_id }) if workspace_id == payload.receipt.workspace_id)
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let now = current_time_micros()?;
        if last_timestamp.is_some_and(|last| now < last) {
            return Err(CommitError::ClockRegression {
                last_timestamp: Timestamp::from_unix_micros(last_timestamp.unwrap_or(now)),
                attempted: Timestamp::from_unix_micros(now),
            });
        }
        let position = next_global_position(&tx)?;
        let next_position = position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let _ = guard_conversation_event(
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            position,
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
        update_stream_head(
            &tx,
            CORRELATION_TYPE_CONVERSATION,
            conversation_id.as_bytes(),
            version,
            payload.receipt.conversation_version,
            *payload.conversation_events[0].event_id(),
            now,
        )?;
        crate::store::snapshot::refresh_aggregate_snapshot(
            &tx,
            CORRELATION_TYPE_CONVERSATION,
            conversation_id.as_bytes(),
        )?;
        update_global_position(&tx, next_position)?;
        persist_claimed_text_receipt(&tx, &payload, &scope, now)?;
        tx.commit()
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        Ok(TextGenerationCommitResult::Committed {
            result: payload.receipt,
        })
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
