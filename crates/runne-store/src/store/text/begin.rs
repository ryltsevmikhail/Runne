use super::super::append_helpers::*;
use super::super::event_guard::*;
use super::super::parse_helpers::*;
use super::super::position_helpers::*;
use super::super::text_receipt_helpers::*;
use super::super::*;

impl StoreTransaction {
    pub(super) fn begin_text_generation_impl(
        &self,
        payload: BeginTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        validate_begin_text_payload(&payload, &self.runtime_authority_id)?;
        let conversation_id = payload.receipt.conversation_id;
        let taskrun_id = payload.receipt.taskrun_id;
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

        if let TextGenerationReceiptLookup::Duplicate { stored_result } = lookup_text_receipt(
            &transaction,
            payload.command_id,
            &payload.idempotency_key,
            &scope,
            &payload.command_fingerprint,
            &self.runtime_authority_id,
        )? {
            return Ok(TextGenerationCommitResult::Duplicate { stored_result });
        }

        // X2 writer lease v1: the first durable mutation acquires the
        // conversation's writer lease; any other principal is fenced until an
        // authenticated take-control rotates it.
        crate::conversation_writer_lease::ensure_writer_lease(
            &transaction,
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

        crate::project_workspace::lineage::record_text_taskrun_lineage(
            &transaction,
            taskrun_id,
            payload.receipt.workspace_id,
            payload.command_id,
            &payload.idempotency_scope,
        )?;

        let (conversation_version, conversation_last_event, conversation_last_timestamp) =
            transaction
                .query_row(
                    "SELECT current_version, last_event_id, last_timestamp
                     FROM aggregate_streams
                     WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                    params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<Vec<u8>>>(1)?,
                            row.get::<_, Option<i64>>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
                .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let conversation_version = u64::try_from(conversation_version)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if conversation_version != payload.expected_conversation_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_conversation_version,
                actual: conversation_version,
            });
        }
        let conversation_last_event = conversation_last_event
            .map(parse_event_id_for_commit)
            .transpose()?;
        if payload.conversation_events[0].causation_id().copied() != conversation_last_event {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let workspace_payload: Vec<u8> = transaction
            .query_row(
                "SELECT payload FROM events
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2 AND sequence = 1",
                params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if !matches!(
            ConversationEventCodec.decode(&workspace_payload),
            Ok(ConversationEvent::ConversationCreated { workspace_id })
                if workspace_id == payload.receipt.workspace_id
        ) {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let taskrun_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM aggregate_streams
                    WHERE aggregate_type = ?1 AND aggregate_id = ?2
                 )",
                params![CORRELATION_TYPE_TASK_RUN, taskrun_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if taskrun_exists {
            return Err(CommitError::VersionConflict {
                expected: 0,
                actual: 1,
            });
        }

        let now = current_time_micros()?;
        if conversation_last_timestamp.is_some_and(|last| now < last) {
            return Err(CommitError::ClockRegression {
                last_timestamp: Timestamp::from_unix_micros(
                    conversation_last_timestamp.unwrap_or(now),
                ),
                attempted: Timestamp::from_unix_micros(now),
            });
        }
        let global_position = next_global_position(&transaction)?;
        let total_events = payload
            .conversation_events
            .len()
            .checked_add(payload.taskrun_events.len())
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let next_global_position = global_position
            .checked_add(
                i64::try_from(total_events).map_err(|_| CommitError::GlobalPositionExhausted)?,
            )
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let conversation_sequence =
            conversation_version
                .checked_add(1)
                .ok_or(CommitError::VersionExhausted {
                    current: conversation_version,
                    event_count: payload.conversation_events.len(),
                })?;
        let _ = guard_conversation_event(
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            conversation_sequence,
            global_position,
            now,
        )?;
        let mut guarded_position = global_position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        for (index, event) in payload.taskrun_events.iter().enumerate() {
            let _ = guard_taskrun_event(
                self.prohibited_content.as_ref(),
                event,
                u64::try_from(index + 1)
                    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
                guarded_position,
                now,
            )?;
            guarded_position = guarded_position
                .checked_add(1)
                .ok_or(CommitError::GlobalPositionExhausted)?;
        }

        transaction
            .execute(
                "INSERT INTO aggregate_streams
                 (aggregate_type, aggregate_id, current_version, last_event_id,
                  last_timestamp, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                params![
                    CORRELATION_TYPE_TASK_RUN,
                    taskrun_id.as_bytes(),
                    payload.receipt.taskrun_version as i64,
                    payload.taskrun_events.last().unwrap().event_id().as_bytes(),
                    now,
                ],
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;

        let mut position = global_position;
        append_conversation_event(
            &transaction,
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            conversation_sequence,
            position,
            now,
        )?;
        position = position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        for (index, event) in payload.taskrun_events.iter().enumerate() {
            append_taskrun_event(
                &transaction,
                self.prohibited_content.as_ref(),
                event,
                u64::try_from(index + 1)
                    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
                position,
                now,
            )?;
            position = position
                .checked_add(1)
                .ok_or(CommitError::GlobalPositionExhausted)?;
        }
        update_stream_head(
            &transaction,
            CORRELATION_TYPE_CONVERSATION,
            conversation_id.as_bytes(),
            conversation_version,
            payload.receipt.conversation_version,
            *payload.conversation_events[0].event_id(),
            now,
        )?;
        crate::store::snapshot::refresh_aggregate_snapshot(
            &transaction,
            CORRELATION_TYPE_CONVERSATION,
            conversation_id.as_bytes(),
        )?;
        crate::store::snapshot::refresh_aggregate_snapshot(
            &transaction,
            CORRELATION_TYPE_TASK_RUN,
            taskrun_id.as_bytes(),
        )?;
        update_global_position(&transaction, next_global_position)?;
        let outcome = TextGenerationReceiptCodec
            .encode(&payload.receipt)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        transaction
            .execute(
                "INSERT INTO command_receipts
                 (command_id, idempotency_scope_bytes, idempotency_key, fingerprint,
                  command_outcome, committed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    payload.command_id.as_bytes(),
                    scope,
                    payload.idempotency_key.as_str().as_bytes(),
                    payload.command_fingerprint.as_bytes(),
                    outcome,
                    now,
                ],
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        transaction
            .commit()
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        Ok(TextGenerationCommitResult::Committed {
            result: payload.receipt,
        })
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
