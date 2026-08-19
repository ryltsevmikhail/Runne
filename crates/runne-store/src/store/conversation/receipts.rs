use super::super::parse_helpers::*;
use super::super::*;

impl StoreTransaction {
    pub(super) fn lookup_conversation_receipt_impl(
        &self,
        command_id: CommandId,
        idempotency_key: &runne_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<ConversationReceiptLookup, CommitError> {
        let conn = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let scope = IdempotencyScopeCodec
            .encode(idempotency_scope)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        if let Some(stored_fingerprint) = conn
            .query_row(
                "SELECT semantic_fingerprint FROM project_workspace_command_receipts
                 WHERE command_id = ?1",
                params![command_id.as_bytes()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(map_commit_read_error)?
        {
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: command_id,
                attempted_command_id: command_id,
                stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
                attempted_fingerprint: *fingerprint,
            });
        }
        let by_command = conn
            .query_row(
                "SELECT idempotency_scope_bytes, idempotency_key, fingerprint, command_outcome
                 FROM command_receipts WHERE command_id = ?1",
                params![command_id.as_bytes()],
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
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if let Some((stored_scope, stored_key, stored_fingerprint, stored_outcome)) = by_command {
            let stored_key = parse_idempotency_key_for_commit(stored_key)?;
            let stored_fingerprint = parse_fingerprint(stored_fingerprint)?;
            if stored_scope == scope
                && stored_key == *idempotency_key
                && stored_fingerprint == *fingerprint
            {
                let stored_result = ConversationReceiptCodec
                    .decode(&stored_outcome)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
                return Ok(ConversationReceiptLookup::Duplicate { stored_result });
            }
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: command_id,
                attempted_command_id: command_id,
                stored_fingerprint,
                attempted_fingerprint: *fingerprint,
            });
        }

        if let Some((stored_command, stored_fingerprint)) = conn
            .query_row(
                "SELECT command_id, fingerprint FROM command_receipts
                 WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
                params![scope, idempotency_key.as_str().as_bytes()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        {
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: parse_command_id_for_commit(stored_command)?,
                attempted_command_id: command_id,
                stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
                attempted_fingerprint: *fingerprint,
            });
        }
        Ok(ConversationReceiptLookup::Miss)
    }
}
