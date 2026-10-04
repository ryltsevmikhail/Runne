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
                "SELECT dispatch_attempt_id, settlement_digest, state, receipt_digest, terminal_sequence
                 FROM provider_terminal_outbox WHERE outbox_id = ?1",
                [outbox_id.as_slice()],
                |row| {
                    Ok((
                        fixed_bytes::<16>(row.get(0)?)?,
                        fixed_bytes::<32>(row.get(1)?)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .ok_or(ProviderExecutionError::OutboxConflict)?;
        let unknown_source = validate_unknown_terminal_outbox_ack(
            &transaction,
            outbox_id,
            existing.0,
            existing.1,
            (existing.2 == 2).then_some(receipt_digest),
        )?;
        if unknown_source && existing.4 == 0 {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        if existing.2 == 2 {
            let ack_matches = existing
                .3
                .as_deref()
                .and_then(|bytes| bytes.try_into().ok())
                == Some(receipt_digest);
            let source_matches = if existing.4 == 0 {
                validate_remote_artifact_ack(
                    &transaction,
                    outbox_id,
                    existing.0,
                    existing.1,
                    receipt_digest,
                    4,
                )?
                .is_some()
            } else {
                true
            };
            return if ack_matches && source_matches {
                Ok(())
            } else {
                Err(ProviderExecutionError::OutboxConflict)
            };
        }
        if existing.2 != 1 || existing.3.is_some() {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        if existing.4 == 0
            && validate_remote_artifact_ack(
                &transaction,
                outbox_id,
                existing.0,
                existing.1,
                receipt_digest,
                2,
            )?
            .is_none()
        {
            return Err(ProviderExecutionError::OutboxConflict);
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
        let updated_attempt = if existing.4 == 0 {
            let completed = transaction
                .execute(
                    "UPDATE provider_dispatch_attempts SET state=5
                     WHERE attempt_id=?1 AND state=4 AND settlement_digest=?2",
                    params![existing.0.as_slice(), existing.1.as_slice()],
                )
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            let preserved_unknown: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM provider_dispatch_attempts
                     WHERE attempt_id=?1 AND state=6 AND settlement_digest IS NULL)",
                    [existing.0.as_slice()],
                    |row| row.get(0),
                )
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            if completed == 1 || preserved_unknown {
                1
            } else {
                0
            }
        } else {
            transaction
                .execute(
                    "UPDATE provider_dispatch_attempts
                     SET state = 5
                     WHERE attempt_id = ?1 AND state = 4 AND settlement_digest = ?2",
                    params![existing.0.as_slice(), existing.1.as_slice()],
                )
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?
        };
        if updated_outbox != 1 || updated_attempt != 1 {
            return Err(ProviderExecutionError::OutboxConflict);
        }
        if existing.4 == 0 {
            let updated_source = transaction
                .execute(
                    "UPDATE provider_remote_terminal_settlements
                 SET settlement_state=4, application_receipt_digest=?3
                 WHERE dispatch_attempt_id=?1 AND source_kind=2 AND settlement_state=2
                   AND settlement_digest=?2",
                    params![
                        existing.0.as_slice(),
                        existing.1.as_slice(),
                        receipt_digest.as_slice()
                    ],
                )
                .map_err(|_| ProviderExecutionError::OutboxConflict)?;
            if updated_source != 1 {
                return Err(ProviderExecutionError::OutboxConflict);
            }
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
