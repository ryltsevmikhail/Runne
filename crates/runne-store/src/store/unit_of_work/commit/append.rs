impl StoreTransaction {
    #[allow(clippy::too_many_arguments)]
    fn append_commit_events(
        &self,
        tx: rusqlite::Transaction<'_>,
        payload: CommandCommit,
        taskrun_id: TaskRunId,
        taskrun_bytes: &[u8; 16],
        scope_bytes: Vec<u8>,
        current_version: i64,
        base_gp: i64,
        new_gp: i64,
        now: i64,
        new_stream: bool,
        permission_terminal: Option<
            crate::store::taskrun_local_command::permission::PermissionTerminalCommitV1<'_, '_>,
        >,
    ) -> Result<CommitResult, CommitError> {
        let event_codec = TaskRunEventCodec;
        let outcome_codec = CommandOutcomeCodec;
        let new_version = current_version + payload.events.len() as i64;
        let envelope_timestamp = Timestamp::from_unix_micros(now);
        #[cfg(target_os = "linux")]
        let permission_terminal_proof = permission_terminal
            .as_ref()
            .map(|terminal| {
                let proof = crate::store::taskrun_local_command::permission::validate_terminal(
                    &tx, self, terminal, &payload,
                )?;
                crate::store::taskrun_local_command::permission::prepare_terminal(
                    &tx, terminal, &proof,
                )?;
                Ok::<_, CommitError>(proof)
            })
            .transpose()?;
        #[cfg(not(target_os = "linux"))]
        let _ = permission_terminal;
        for (i, event) in payload.events.iter().enumerate() {
            if permission_terminal.is_none() {
                crate::store::event_guard::guard_local_command_terminal(&tx, event)?;
            }
            let sequence = u64::try_from(current_version + 1 + i as i64)
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
            let global_position = base_gp
                .checked_add(i as i64)
                .ok_or(CommitError::GlobalPositionExhausted)?;
            let _ = guard_taskrun_event(
                self.prohibited_content.as_ref(),
                event,
                sequence,
                global_position,
                now,
            )?;
        }
        if new_stream {
            tx.execute(
                "INSERT INTO aggregate_streams
                 (aggregate_type, aggregate_id, current_version, last_event_id,
                  last_timestamp, created_at)
                 VALUES (?1, ?2, 0, NULL, NULL, ?3)",
                params![CORRELATION_TYPE_TASK_RUN, taskrun_bytes, now_micros()],
            )
            .map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;
        }

        for (i, event) in payload.events.iter().enumerate() {
            let seq = current_version + 1 + i as i64;
            let gp = base_gp + i as i64;

            let payload_bytes = event_codec.encode(event.payload()).map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;

            let correlation_id = match event.correlation_id() {
                AggregateId::TaskRun(correlation_id) if *correlation_id == taskrun_id => {
                    correlation_id
                }
                _ => {
                    return Err(CommitError::StorageFailure(
                        runne_application::ports::StorageFailureKind::IntegrityViolation,
                    ));
                }
            };

            let aggregate_id = AggregateId::TaskRun(taskrun_id);
            let temp_envelope = EventEnvelope::from_parts(
                *event.event_id(),
                aggregate_id.clone(),
                AggregateId::TaskRun(*correlation_id),
                event.causation_id().copied(),
                *event.command_id(),
                event.idempotency_key().clone(),
                event.schema_version(),
                event.actor().clone(),
                *event.sensitivity(),
                event.payload().clone(),
                seq as u64,
                envelope_timestamp,
                IntegrityDigest::from_bytes([0; 32]),
            );

            let digest =
                compute_integrity_digest_with_global_position(&temp_envelope, gp, &payload_bytes)
                    .map_err(|_| {
                    CommitError::StorageFailure(
                        runne_application::ports::StorageFailureKind::IntegrityViolation,
                    )
                })?;

            let causation_bytes: Option<&[u8]> =
                event.causation_id().map(|eid| eid.as_bytes() as &[u8]);

            tx.execute(
                "INSERT INTO events
                 (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
                  sensitivity, schema_version, causation_id,
                  command_id, idempotency_key, actor, payload, integrity_digest,
                  correlation_id, correlation_type, integrity_profile)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                         ?15, ?16, ?17)",
                params![
                    event.event_id().as_bytes(),
                    CORRELATION_TYPE_TASK_RUN,
                    taskrun_bytes,
                    seq,
                    gp,
                    now,
                    sensitivity_value(*event.sensitivity()),
                    event.schema_version() as i64,
                    causation_bytes,
                    event.command_id().as_bytes(),
                    event.idempotency_key().as_str().as_bytes(),
                    event.actor().as_str().as_bytes(),
                    payload_bytes,
                    digest.as_bytes(),
                    correlation_id.as_bytes(),
                    StoredCorrelationType::TaskRun.as_i64(),
                    INTEGRITY_PROFILE_V1,
                ],
            )
            .map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;
        }

        let last_event = payload.events.last().unwrap();
        if current_version == 0 {
            tx.execute(
                "UPDATE aggregate_streams
                 SET current_version = ?1, last_event_id = ?2, last_timestamp = ?3
                 WHERE aggregate_type = ?4 AND aggregate_id = ?5",
                params![
                    new_version,
                    last_event.event_id().as_bytes(),
                    now,
                    CORRELATION_TYPE_TASK_RUN,
                    taskrun_bytes,
                ],
            )
            .map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;
        } else {
            tx.execute(
                "UPDATE aggregate_streams
                 SET current_version = ?1, last_event_id = ?2, last_timestamp = ?3
                 WHERE aggregate_type = ?4 AND aggregate_id = ?5",
                params![
                    new_version,
                    last_event.event_id().as_bytes(),
                    now,
                    CORRELATION_TYPE_TASK_RUN,
                    taskrun_bytes,
                ],
            )
            .map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;
        }

        for (index, event) in payload.events.iter().enumerate() {
            if matches!(
                event.payload(),
                runne_domain::task_run::TaskRunEvent::CancellationRequested
            ) {
                let sequence = current_version + 1 + index as i64;
                crate::provider::record_taskrun_provider_cancel_fence(
                    &tx,
                    taskrun_id,
                    *event.event_id(),
                    sequence,
                    now,
                )
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
                crate::store::taskrun_local_command::permission::record_cancellation_stops(
                    &tx,
                    taskrun_id,
                    sequence as u64,
                    event.event_id().as_bytes(),
                    now,
                )
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
            }
        }

        crate::store::snapshot::refresh_aggregate_snapshot(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            taskrun_bytes,
        )?;

        if let Some(first) = payload.events.first() {
            crate::store::taskrun_local_command::insert_preflight(
                &tx,
                taskrun_id,
                first.payload(),
                now,
            )
            .map_err(|_| CommitError::StorageFailure(StorageFailureKind::IntegrityViolation))?;
        }

        // Update global position
        tx.execute(
            "UPDATE event_log_state SET next_global_position = ?1 WHERE singleton = 1",
            params![new_gp],
        )
        .map_err(|_| {
            CommitError::StorageFailure(
                runne_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        #[cfg(target_os = "linux")]
        if let (Some(terminal), Some(proof)) = (
            permission_terminal.as_ref(),
            permission_terminal_proof.as_ref(),
        ) {
            crate::store::taskrun_local_command::permission::write_terminal(
                &tx, terminal, proof, now,
            )?;
        }

        // Insert receipt
        let outcome_bytes = outcome_codec.encode(&payload.command_result).map_err(|_| {
            CommitError::StorageFailure(
                runne_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        tx.execute(
            "INSERT INTO command_receipts
             (command_id, idempotency_scope_bytes, idempotency_key,
              fingerprint, command_outcome, committed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                payload.command_id.as_bytes(),
                scope_bytes,
                payload.idempotency_key.as_str().as_bytes(),
                payload.command_fingerprint.as_bytes(),
                outcome_bytes,
                now,
            ],
        )
        .map_err(|_| {
            CommitError::StorageFailure(
                runne_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        // Step 9: Commit transaction
        tx.commit().map_err(|_| {
            CommitError::StorageFailure(
                runne_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;
        #[cfg(feature = "test-support")]
        super::super::commit_gate::note_command_outcome(&payload);

        Ok(CommitResult::Committed {
            new_version: new_version as u64,
        })
    }
}
