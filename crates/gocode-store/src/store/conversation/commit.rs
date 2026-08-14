use super::super::component_guard::*;
use super::super::event_guard::*;
use super::super::parse_helpers::*;
use super::super::snapshot::refresh_conversation_snapshot;
use super::super::*;

impl StoreTransaction {
    pub(super) fn commit_conversation_impl(
        &self,
        payload: ConversationCommit,
    ) -> Result<ConversationCommitResult, CommitError> {
        let mut conn = self
            .inner
            .writer
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let scope = IdempotencyScopeCodec
            .encode(&payload.idempotency_scope)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;

        if let Some(stored_fingerprint) = tx
            .query_row(
                "SELECT semantic_fingerprint FROM project_workspace_command_receipts
                 WHERE command_id = ?1",
                params![payload.command_id.as_bytes()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(map_commit_read_error)?
        {
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: payload.command_id,
                attempted_command_id: payload.command_id,
                stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
                attempted_fingerprint: payload.command_fingerprint,
            });
        }

        if let Some((stored_scope, stored_key, stored_fingerprint, stored_outcome)) = tx
            .query_row(
                "SELECT idempotency_scope_bytes, idempotency_key, fingerprint, command_outcome
                 FROM command_receipts WHERE command_id = ?1",
                params![payload.command_id.as_bytes()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        {
            let stored_key = parse_idempotency_key_for_commit(stored_key)?;
            let stored_fingerprint = parse_fingerprint(stored_fingerprint)?;
            if stored_scope == scope
                && stored_key == payload.idempotency_key
                && stored_fingerprint == payload.command_fingerprint
            {
                let stored_result = ConversationReceiptCodec
                    .decode(&stored_outcome)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
                return Ok(ConversationCommitResult::Duplicate { stored_result });
            }
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: payload.command_id,
                attempted_command_id: payload.command_id,
                stored_fingerprint,
                attempted_fingerprint: payload.command_fingerprint,
            });
        }
        if let Some((stored_command, stored_fingerprint)) = tx
            .query_row(
                "SELECT command_id, fingerprint FROM command_receipts
                 WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
                params![scope, payload.idempotency_key.as_str().as_bytes()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        {
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: parse_command_id_for_commit(stored_command)?,
                attempted_command_id: payload.command_id,
                stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
                attempted_fingerprint: payload.command_fingerprint,
            });
        }

        if payload.events.len() != 1 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let event = &payload.events[0];
        let conversation_id = match (event.aggregate_id(), event.correlation_id()) {
            (AggregateId::Conversation(aggregate), AggregateId::Conversation(correlation))
                if aggregate == correlation =>
            {
                *aggregate
            }
            _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
        };
        match event.payload() {
            ConversationEvent::ConversationCreated { workspace_id }
                if *workspace_id == payload.workspace_id => {}
            _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
        }
        let scope_matches = matches!(
            &payload.idempotency_scope,
            IdempotencyScope {
                runtime_authority_id,
                operation: OperationTag::CreateConversation,
                aggregate_scope:
                    AggregateScope::NewConversation {
                        conversation_id: scoped_conversation_id,
                        workspace_id: scoped_workspace_id,
                    },
                ..
            } if runtime_authority_id == &self.runtime_authority_id
                && scoped_conversation_id == &conversation_id
                && scoped_workspace_id == &payload.workspace_id
        );
        let expected_fingerprint =
            CommandFingerprint::for_create_conversation(&conversation_id, &payload.workspace_id);
        if !scope_matches
            || event.command_id() != &payload.command_id
            || event.idempotency_key() != &payload.idempotency_key
            || payload.command_fingerprint != expected_fingerprint
            || event.schema_version() != 1
            || event.sensitivity() != &Sensitivity::Public
            || event.causation_id().is_some()
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }

        let existing_version = tx
            .query_row(
                "SELECT current_version FROM aggregate_streams
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if let Some(actual) = existing_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_version,
                actual: u64::try_from(actual)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
            });
        }
        if payload.expected_version != 0 {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_version,
                actual: 0,
            });
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CommitError::ClockFailure)
            .and_then(|duration| {
                i64::try_from(duration.as_micros()).map_err(|_| CommitError::ClockFailure)
            })?;
        let global_position = tx
            .query_row(
                "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let next_global_position = global_position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let timestamp = Timestamp::from_unix_micros(now);
        let payload_bytes = ConversationEventCodec
            .encode(event.payload())
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let envelope = EventEnvelope::from_parts(
            *event.event_id(),
            AggregateId::Conversation(conversation_id),
            AggregateId::Conversation(conversation_id),
            event.causation_id().copied(),
            *event.command_id(),
            event.idempotency_key().clone(),
            event.schema_version(),
            event.actor().clone(),
            *event.sensitivity(),
            event.payload().clone(),
            1,
            timestamp,
            IntegrityDigest::from_bytes([0; 32]),
        );
        let digest = compute_integrity_digest_v2_with_global_position(
            &envelope,
            global_position,
            &payload_bytes,
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        enforce_conversation_replay_size(
            event,
            conversation_id,
            1,
            global_position,
            now,
            &payload_bytes,
            digest,
        )?;
        guard_event_components(
            self.prohibited_content.as_ref(),
            event,
            CORRELATION_TYPE_CONVERSATION,
            conversation_id.as_bytes(),
            1,
            global_position,
            now,
            &payload_bytes,
            digest,
            INTEGRITY_PROFILE_V2,
        )?;

        tx.execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id,
              last_timestamp, created_at)
             VALUES (?1, ?2, 1, ?3, ?4, ?4)",
            params![
                CORRELATION_TYPE_CONVERSATION,
                conversation_id.as_bytes(),
                event.event_id().as_bytes(),
                now,
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        tx.execute(
            "INSERT INTO events
             (event_id, aggregate_type, aggregate_id, sequence, global_position,
              timestamp, sensitivity, schema_version, causation_id, command_id,
              idempotency_key, actor, payload, integrity_digest, correlation_id,
              correlation_type, integrity_profile)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, 0, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?3, ?2, ?13)",
            params![
                event.event_id().as_bytes(),
                CORRELATION_TYPE_CONVERSATION,
                conversation_id.as_bytes(),
                global_position,
                now,
                event.schema_version() as i64,
                event.causation_id().map(EventId::as_bytes),
                event.command_id().as_bytes(),
                event.idempotency_key().as_str().as_bytes(),
                event.actor().as_str().as_bytes(),
                payload_bytes,
                digest.as_bytes(),
                INTEGRITY_PROFILE_V2,
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        tx.execute(
            "UPDATE event_log_state SET next_global_position = ?1 WHERE singleton = 1",
            params![next_global_position],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        refresh_conversation_snapshot(&tx, conversation_id)?;

        let result = ConversationReceipt {
            conversation_id,
            workspace_id: payload.workspace_id,
            new_version: 1,
            committed_at: timestamp,
        };
        let outcome = ConversationReceiptCodec
            .encode(&result)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        tx.execute(
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
        tx.commit()
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        Ok(ConversationCommitResult::Committed { result })
    }
}
