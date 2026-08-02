use super::super::parse_helpers::*;
use super::super::*;

impl StoreTransaction {
    pub(super) fn lookup_receipt_impl(
        &self,
        command_id: CommandId,
        idempotency_key: &gocode_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<ReceiptLookup, CommitError> {
        let mut conn = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = conn.transaction().map_err(map_commit_read_error)?;

        let scope_codec = IdempotencyScopeCodec;
        let scope_bytes = scope_codec.encode(idempotency_scope).map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        let cmd_id_bytes = command_id.as_bytes();
        let ikey_bytes = idempotency_key.as_str().as_bytes();

        // Check by command_id first
        let by_cmd_id: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT idempotency_scope_bytes, fingerprint, command_outcome
                 FROM command_receipts
                 WHERE command_id = ?1",
                params![cmd_id_bytes],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(map_commit_read_error)?;

        if let Some((stored_scope, stored_fp, outcome_bytes)) = by_cmd_id {
            let stored_fp_arr: [u8; 32] = stored_fp.try_into().unwrap_or([0; 32]);
            let stored_fingerprint = CommandFingerprint::from_bytes(stored_fp_arr);

            if stored_scope == scope_bytes && stored_fingerprint == *fingerprint {
                let outcome_codec = CommandOutcomeCodec;
                let stored_result = outcome_codec.decode(&outcome_bytes).map_err(|_| {
                    CommitError::StorageFailure(
                        gocode_application::ports::StorageFailureKind::CorruptData,
                    )
                })?;
                return Ok(ReceiptLookup::Duplicate { stored_result });
            } else {
                return Err(CommitError::IdempotencyConflict {
                    stored_command_id: command_id,
                    attempted_command_id: command_id,
                    stored_fingerprint,
                    attempted_fingerprint: *fingerprint,
                });
            }
        }

        // Check by (scope_bytes, idempotency_key)
        let by_scope: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT command_id, fingerprint
                 FROM command_receipts
                 WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
                params![scope_bytes, ikey_bytes],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(map_commit_read_error)?;

        if let Some((stored_cmd, stored_fp)) = by_scope {
            let stored_cmd_id = CommandId::from_bytes(stored_cmd.try_into().unwrap_or([0; 16]));
            let stored_fp_arr: [u8; 32] = stored_fp.try_into().unwrap_or([0; 32]);
            let stored_fingerprint = CommandFingerprint::from_bytes(stored_fp_arr);
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: stored_cmd_id,
                attempted_command_id: command_id,
                stored_fingerprint,
                attempted_fingerprint: *fingerprint,
            });
        }

        tx.commit().map_err(map_commit_read_error)?;
        Ok(ReceiptLookup::Miss)
    }
}
