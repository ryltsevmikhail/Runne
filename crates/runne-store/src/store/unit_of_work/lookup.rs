use super::super::parse_helpers::*;
use super::super::*;

impl StoreTransaction {
    pub(super) fn lookup_receipt_impl(
        &self,
        command_id: CommandId,
        idempotency_key: &runne_domain::id::IdempotencyKey,
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
                runne_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        let cmd_id_bytes = command_id.as_bytes();
        let ikey_bytes = idempotency_key.as_str().as_bytes();

        let project_fingerprint = tx
            .query_row(
                "SELECT semantic_fingerprint FROM project_workspace_command_receipts
                 WHERE command_id = ?1",
                params![cmd_id_bytes],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(map_commit_read_error)?;
        if let Some(stored_fingerprint) = project_fingerprint {
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: command_id,
                attempted_command_id: command_id,
                stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
                attempted_fingerprint: *fingerprint,
            });
        }

        // Check by command_id first.
        let by_cmd_id = tx
            .query_row(
                "SELECT idempotency_scope_bytes, idempotency_key, fingerprint, command_outcome
                 FROM command_receipts
                 WHERE command_id = ?1",
                params![cmd_id_bytes],
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
            .map_err(map_commit_read_error)?;

        if let Some((stored_scope, stored_key, stored_fp, outcome_bytes)) = by_cmd_id {
            let stored_key = parse_idempotency_key_for_commit(stored_key)?;
            let stored_fingerprint = parse_fingerprint(stored_fp)?;

            if stored_scope == scope_bytes
                && stored_key == *idempotency_key
                && stored_fingerprint == *fingerprint
            {
                let outcome_codec = CommandOutcomeCodec;
                let stored_result = outcome_codec.decode(&outcome_bytes).map_err(|_| {
                    CommitError::StorageFailure(
                        runne_application::ports::StorageFailureKind::CorruptData,
                    )
                })?;
                if idempotency_scope.operation == OperationTag::CreateTaskRun {
                    let runne_application::commands::CommandOutcome::TaskRunCreated {
                        taskrun_id,
                        new_version: 1,
                    } = &stored_result
                    else {
                        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
                    };
                    crate::project_workspace::lineage::validate_direct_taskrun_lineage(
                        &tx,
                        idempotency_scope,
                        *taskrun_id,
                        command_id,
                    )?;
                }
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
            let stored_cmd_id = parse_command_id_for_commit(stored_cmd)?;
            let stored_fingerprint = parse_fingerprint(stored_fp)?;
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
