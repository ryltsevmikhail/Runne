impl SqliteProviderExecutionStore {
    fn activate_journal_key_impl(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let runtime = load_runtime_authority(&transaction)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .ok_or(ProviderExecutionError::JournalKeyUnavailable)?;
        if key.runtime_authority_id() != runtime.runtime_authority_id
            || key.database_generation() != runtime.database_generation
        {
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        if let Some(stored) = load_journal_key_state(&transaction, key)? {
            if stored == JournalKeyState::Active {
                return Ok(());
            }
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        if let Some(active) = load_active_journal_key(&transaction)? {
            if key.key_version() <= active.binding.key_version() {
                return Err(ProviderExecutionError::JournalKeyUnavailable);
            }
            transaction
                .execute(
                    "UPDATE provider_journal_key_refs
                     SET state = 2, active_slot = NULL, retired_at = ?3
                     WHERE key_id = ?1 AND key_version = ?2
                       AND state = 1 AND active_slot = 1",
                    params![
                        active.binding.key_id().as_slice(),
                        execution_i64(active.binding.key_version())?,
                        unix_timestamp(),
                    ],
                )
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        }
        transaction
            .execute(
                "INSERT INTO provider_journal_key_refs (
                    key_id, key_version, runtime_authority_id, database_generation,
                    state, active_slot, created_at, retired_at
                 ) VALUES (?1, ?2, ?3, ?4, 1, 1, ?5, NULL)",
                params![
                    key.key_id().as_slice(),
                    execution_i64(key.key_version())?,
                    key.runtime_authority_id().as_slice(),
                    execution_i64(key.database_generation())?,
                    unix_timestamp(),
                ],
            )
            .map_err(|_| ProviderExecutionError::JournalKeyUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }

}
impl SqliteProviderExecutionStore {
    fn journal_key_reference_count_impl(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<u64, ProviderExecutionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        ensure_journal_key_exists(&connection, key)?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM provider_encryption_nonces
                 WHERE key_id = ?1 AND key_version = ?2",
                params![key.key_id().as_slice(), execution_i64(key.key_version())?,],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        u64::try_from(count).map_err(|_| ProviderExecutionError::JournalCorrupt)
    }

}
impl SqliteProviderExecutionStore {
    fn remove_retired_journal_key_impl(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if load_journal_key_state(&transaction, key)? != Some(JournalKeyState::Retired) {
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        let references: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM provider_encryption_nonces
                 WHERE key_id = ?1 AND key_version = ?2",
                params![key.key_id().as_slice(), execution_i64(key.key_version())?,],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if references != 0 {
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        let changed = transaction
            .execute(
                "DELETE FROM provider_journal_key_refs
                 WHERE key_id = ?1 AND key_version = ?2 AND state = 2",
                params![key.key_id().as_slice(), execution_i64(key.key_version())?,],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if changed != 1 {
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }

}
impl SqliteProviderExecutionStore {
    fn begin_provider_poll_impl(
        &self,
        request: &ProviderPollRequest,
    ) -> Result<(), ProviderExecutionError> {
        validate_poll_request(request)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&transaction, request.attempt_id)?;
        verify_attempt_for_progress(
            &attempt,
            request.fencing_token,
            request.runtime_generation,
            request.profile_digest,
        )?;
        verify_current_runtime_lease(&transaction, &attempt)?;
        if attempt.state == 6 {
            return Err(ProviderExecutionError::AttemptUncertain);
        }
        if attempt.state != 3 {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let next_sequence = next_journal_sequence(&transaction, request.attempt_id)?;
        if request.cursor != next_sequence {
            return Err(ProviderExecutionError::SequenceMismatch);
        }
        let existing = transaction
            .query_row(
                "SELECT cursor, runtime_generation, fencing_token
                 FROM provider_poll_flights WHERE dispatch_attempt_id = ?1",
                [request.attempt_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        nonnegative_u64(row.get(0)?)?,
                        positive_u64(row.get(1)?)?,
                        positive_u64(row.get(2)?)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if existing.is_some() {
            let changed = transaction
                .execute(
                    "UPDATE provider_dispatch_attempts SET state = 6
                     WHERE attempt_id = ?1 AND state = 3",
                    [request.attempt_id.as_bytes().as_slice()],
                )
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            if changed != 1 {
                return Err(ProviderExecutionError::AttemptUncertain);
            }
            transaction
                .commit()
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            return Err(ProviderExecutionError::AttemptUncertain);
        }
        transaction
            .execute(
                "INSERT INTO provider_poll_flights (
                    dispatch_attempt_id, cursor, runtime_generation, fencing_token, opened_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    request.attempt_id.as_bytes().as_slice(),
                    execution_i64(request.cursor)?,
                    execution_i64(request.runtime_generation)?,
                    execution_i64(request.fencing_token)?,
                    unix_timestamp(),
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }

}
