impl StoreTransaction {
    fn commit_transaction(
        &self,
        tx: rusqlite::Transaction<'_>,
        payload: CommandCommit,
        taskrun_id: TaskRunId,
        taskrun_bytes: &[u8; 16],
    ) -> Result<CommitResult, CommitError> {
        // Step 1: Receipt lookup inside transaction
        let scope_codec = IdempotencyScopeCodec;
        let scope_bytes = scope_codec
            .encode(&payload.idempotency_scope)
            .map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;

        let project_fingerprint = tx
            .query_row(
                "SELECT semantic_fingerprint FROM project_workspace_command_receipts
                 WHERE command_id = ?1",
                params![payload.command_id.as_bytes()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::CorruptData,
                )
            })?;
        if let Some(stored_fingerprint) = project_fingerprint {
            let stored_fingerprint = stored_fingerprint.try_into().map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::CorruptData,
                )
            })?;
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: payload.command_id,
                attempted_command_id: payload.command_id,
                stored_fingerprint: CommandFingerprint::from_bytes(stored_fingerprint),
                attempted_fingerprint: payload.command_fingerprint,
            });
        }

        // Dedup by command_id
        let existing = tx
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
            .map_err(map_commit_read_error)?;

        if let Some((stored_scope, stored_key, stored_fingerprint, outcome_bytes)) = existing {
            let stored_key = parse_idempotency_key_for_commit(stored_key)?;
            let stored_fingerprint = parse_fingerprint(stored_fingerprint)?;
            if stored_scope == scope_bytes
                && stored_key == payload.idempotency_key
                && stored_fingerprint == payload.command_fingerprint
            {
                let outcome_codec = CommandOutcomeCodec;
                let stored_result = outcome_codec.decode(&outcome_bytes).map_err(|_| {
                    CommitError::StorageFailure(
                        runne_application::ports::StorageFailureKind::CorruptData,
                    )
                })?;
                if payload.idempotency_scope.operation
                    == runne_application::ports::OperationTag::CreateTaskRun
                {
                    let runne_application::commands::CommandOutcome::TaskRunCreated {
                        taskrun_id: stored_taskrun_id,
                        new_version: 1,
                    } = &stored_result
                    else {
                        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
                    };
                    crate::project_workspace::lineage::validate_direct_taskrun_lineage(
                        &tx,
                        &payload.idempotency_scope,
                        *stored_taskrun_id,
                        payload.command_id,
                    )?;
                }
                tx.commit().map_err(|_| {
                    CommitError::StorageFailure(
                        runne_application::ports::StorageFailureKind::IntegrityViolation,
                    )
                })?;
                return Ok(CommitResult::Duplicate { stored_result });
            } else {
                return Err(CommitError::IdempotencyConflict {
                    stored_command_id: payload.command_id,
                    attempted_command_id: payload.command_id,
                    stored_fingerprint,
                    attempted_fingerprint: payload.command_fingerprint,
                });
            }
        }

        // Check scope+key collision
        let scope_key_collision = tx
            .query_row(
                "SELECT command_id, fingerprint FROM command_receipts
                 WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
                params![scope_bytes, payload.idempotency_key.as_str().as_bytes(),],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(map_commit_read_error)?;

        if let Some((stored_command, stored_fingerprint)) = scope_key_collision {
            let _ = tx.rollback();
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: parse_command_id_for_commit(stored_command)?,
                attempted_command_id: payload.command_id,
                stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
                attempted_fingerprint: payload.command_fingerprint,
            });
        }

        // A new TaskRun cannot race a Project deletion after Project/Workspace
        // authority has been activated. Exact receipt replay remains independent
        // of current Workspace lifecycle state.
        crate::project_workspace::lineage::record_direct_taskrun_lineage(
            &tx,
            &payload.idempotency_scope,
            taskrun_id,
            payload.command_id,
        )?;

        // Step 2: Version check
        let stream_row = tx
            .query_row(
                "SELECT current_version, last_timestamp
                 FROM aggregate_streams
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                params![CORRELATION_TYPE_TASK_RUN, taskrun_bytes],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()
            .map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::CorruptData,
                )
            })?;

        let (current_version, last_timestamp, new_stream) = match stream_row {
            Some((version, timestamp)) => (version, timestamp, false),
            None if payload.expected_version == 0 => (0, None, true),
            None => {
                let _ = tx.rollback();
                return Err(CommitError::VersionConflict {
                    expected: payload.expected_version,
                    actual: 0,
                });
            }
        };

        if payload.expected_version != current_version as u64 {
            let _ = tx.rollback();
            return Err(CommitError::VersionConflict {
                expected: payload.expected_version,
                actual: current_version as u64,
            });
        }

        // Step 3: Clock check
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CommitError::ClockFailure)?
            .as_micros() as i64;

        if let Some(last_ts) = last_timestamp
            && now < last_ts
        {
            let _ = tx.rollback();
            return Err(CommitError::ClockRegression {
                last_timestamp: Timestamp::from_unix_micros(last_ts),
                attempted: Timestamp::from_unix_micros(now),
            });
        }

        // Step 4: Allocate global position
        let base_gp: i64 = tx
            .query_row(
                "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::CorruptData,
                )
            })?;

        let new_gp = base_gp
            .checked_add(payload.events.len() as i64)
            .ok_or(CommitError::GlobalPositionExhausted)?;

        self.append_commit_events(
            tx,
            payload,
            taskrun_id,
            taskrun_bytes,
            scope_bytes,
            current_version,
            base_gp,
            new_gp,
            now,
            new_stream,
        )
    }

}
