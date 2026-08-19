impl SqliteProviderExecutionStore {
    fn pending_terminal_outbox_impl(
        &self,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT outbox.outbox_id, outbox.dispatch_attempt_id,
                        outbox.terminal_sequence, outbox.call_digest_version,
                        outbox.key_id, outbox.key_version, keys.runtime_authority_id,
                        keys.database_generation, outbox.nonce, outbox.runtime_generation,
                        outbox.profile_digest, outbox.ciphertext, outbox.plaintext_len,
                        outbox.plaintext_digest, outbox.settlement_digest,
                        outbox.application_idempotency_key, admission.principal_id,
                        admission.conversation_id, admission.taskrun_id,
                        admission.execution_attempt_id, admission.fencing_token
                 FROM provider_terminal_outbox outbox
                 JOIN provider_journal_key_refs keys
                   ON keys.key_id = outbox.key_id AND keys.key_version = outbox.key_version
                 JOIN provider_execution_admissions admission
                   ON admission.dispatch_attempt_id = outbox.dispatch_attempt_id
                 WHERE outbox.state = 1
                 ORDER BY outbox.created_at, outbox.outbox_id",
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        statement
            .query_map([], |row| {
                let key = ProviderJournalKeyBinding::new(
                    fixed_bytes(row.get(4)?)?,
                    positive_u64(row.get(5)?)?,
                    fixed_bytes(row.get(6)?)?,
                    positive_u64(row.get(7)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let encrypted_output = ProviderEncryptedPayload::new(
                    fixed_bytes(row.get(8)?)?,
                    row.get(11)?,
                    nonnegative_u64(row.get(12)?)?,
                    fixed_bytes(row.get(13)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(ProviderTerminalOutboxRecord {
                    outbox_id: fixed_bytes(row.get(0)?)?,
                    attempt_id: DispatchAttemptId::from_bytes(fixed_bytes(row.get(1)?)?),
                    fencing_token: positive_u64(row.get(20)?)?,
                    principal_id: row.get(16)?,
                    conversation_id: ConversationId::from_bytes(fixed_bytes(row.get(17)?)?),
                    taskrun_id: TaskRunId::from_bytes(fixed_bytes(row.get(18)?)?),
                    execution_attempt_id: AttemptId::from_bytes(fixed_bytes(row.get(19)?)?),
                    terminal_sequence: nonnegative_u64(row.get(2)?)?,
                    call_digest_version: decode_call_digest_version(row.get(3)?)?,
                    key,
                    encrypted_output,
                    runtime_generation: positive_u64(row.get(9)?)?,
                    profile_digest: fixed_bytes(row.get(10)?)?,
                    settlement_digest: fixed_bytes(row.get(14)?)?,
                    application_idempotency_key: row.get(15)?,
                })
            })
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| ProviderExecutionError::JournalCorrupt)
    }

}
impl SqliteProviderExecutionStore {
    fn acknowledge_terminal_outbox_impl(
        &self,
        outbox_id: [u8; 16],
        receipt_digest: [u8; 32],
    ) -> Result<(), ProviderExecutionError> {
        if outbox_id == [0; 16] || receipt_digest == [0; 32] {
            return Err(ProviderExecutionError::OutboxConflict);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let existing = transaction
            .query_row(
                "SELECT dispatch_attempt_id, settlement_digest, state, receipt_digest
                 FROM provider_terminal_outbox WHERE outbox_id = ?1",
                [outbox_id.as_slice()],
                |row| {
                    Ok((
                        fixed_bytes::<16>(row.get(0)?)?,
                        fixed_bytes::<32>(row.get(1)?)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .ok_or(ProviderExecutionError::OutboxConflict)?;
        if existing.2 == 2 {
            return if existing
                .3
                .as_deref()
                .and_then(|bytes| bytes.try_into().ok())
                == Some(receipt_digest)
            {
                Ok(())
            } else {
                Err(ProviderExecutionError::OutboxConflict)
            };
        }
        if existing.2 != 1 || existing.3.is_some() {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        let now = unix_timestamp();
        let updated_outbox = transaction
            .execute(
                "UPDATE provider_terminal_outbox
                 SET state = 2, receipt_digest = ?2, applied_at = ?3
                 WHERE outbox_id = ?1 AND state = 1 AND receipt_digest IS NULL",
                params![outbox_id.as_slice(), receipt_digest.as_slice(), now],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let updated_attempt = transaction
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = 5
                 WHERE attempt_id = ?1 AND state = 4 AND settlement_digest = ?2",
                params![existing.0.as_slice(), existing.1.as_slice()],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if updated_outbox != 1 || updated_attempt != 1 {
            return Err(ProviderExecutionError::OutboxConflict);
        }
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }

}
impl SqliteProviderExecutionStore {
    fn mark_execution_uncertain_impl(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderExecutionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&transaction, attempt_id)?;
        if attempt.fencing_token != fencing_token {
            return Err(ProviderExecutionError::StaleGeneration);
        }
        verify_current_runtime_lease(&transaction, &attempt)?;
        let current = attempt.state;
        if current == 6 {
            return Ok(());
        }
        if !matches!(current, 1 | 3) {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let changed = transaction
            .execute(
                "UPDATE provider_dispatch_attempts SET state = 6
                 WHERE attempt_id = ?1 AND fencing_token = ?2 AND state IN (1, 3)",
                params![
                    attempt_id.as_bytes().as_slice(),
                    execution_i64(fencing_token)?,
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if changed != 1 {
            return Err(ProviderExecutionError::StaleGeneration);
        }
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }
}
