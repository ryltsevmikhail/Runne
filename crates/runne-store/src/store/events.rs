use super::parse_helpers::*;
use super::*;

impl AppEventStore for StoreTransaction {
    fn list_task_runs(&self) -> Result<Vec<TaskRunId>, EventStoreError> {
        let conn = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let mut statement = conn
            .prepare(
                "SELECT aggregate_id
                 FROM aggregate_streams
                 WHERE aggregate_type = ?1
                 ORDER BY aggregate_id ASC",
            )
            .map_err(map_event_store_read_error)?;
        statement
            .query_map(params![CORRELATION_TYPE_TASK_RUN], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(map_event_store_read_error)?
            .map(|row| {
                let bytes = row.map_err(map_event_store_read_error)?;
                let bytes: [u8; 16] = bytes.try_into().map_err(|_| EventStoreError::CorruptData)?;
                Ok(TaskRunId::from_bytes(bytes))
            })
            .collect()
    }

    fn load_task_run_effects(
        &self,
        taskrun_id: TaskRunId,
    ) -> Result<runne_api::TaskRunEffectsV1, EventStoreError> {
        load_task_run_effects_from_store(self, taskrun_id)
    }

    fn load_task_run_effects_with_remote_authenticator(
        &self,
        taskrun_id: TaskRunId,
        authenticator: Option<&dyn runne_application::provider::ProviderRemoteFactAuthenticator>,
        resolver: Option<&dyn runne_application::provider::HistoricalProviderModelResolver>,
    ) -> Result<runne_application::ports::TaskRunEffectsReadSnapshot, EventStoreError> {
        self.load_task_run_effects_with_fact_authenticators(
            taskrun_id,
            authenticator,
            None,
            resolver,
        )
    }

    fn load_task_run_effects_with_fact_authenticators(
        &self,
        taskrun_id: TaskRunId,
        authenticator: Option<&dyn runne_application::provider::ProviderRemoteFactAuthenticator>,
        source1_authenticator: Option<
            &dyn runne_application::provider::ProviderUnknownTerminalFactAuthenticator,
        >,
        resolver: Option<&dyn runne_application::provider::HistoricalProviderModelResolver>,
    ) -> Result<runne_application::ports::TaskRunEffectsReadSnapshot, EventStoreError> {
        let mut connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction()
            .map_err(map_event_store_read_error)?;
        let successor_eligibility = match resolver {
            Some(resolver) => {
                crate::store::unknown_successor::unknown_successor_eligibility_in_transaction(
                    &tx,
                    &self.runtime_authority_id,
                    taskrun_id,
                    crate::store::taskrun_claim::stream_validate::verify_stream(
                        &tx, taskrun_id, None,
                    )
                    .map_err(|_| EventStoreError::CorruptData)?
                    .version,
                    resolver,
                )
                .map_err(|_| EventStoreError::CorruptData)?
            }
            None => runne_api::SuccessorEligibilityV1::Blocked,
        };
        let snapshot = load_task_run_effects_snapshot_in_transaction(
            &tx,
            &self.runtime_authority_id,
            taskrun_id,
            authenticator,
            source1_authenticator,
            successor_eligibility,
        )?;
        tx.commit().map_err(map_event_store_read_error)?;
        Ok(snapshot)
    }

    fn load_task_run(&self, taskrun_id: TaskRunId) -> Result<LoadedStream, EventStoreError> {
        let mut conn = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = conn.transaction().map_err(map_event_store_read_error)?;
        let taskrun_bytes = taskrun_id.as_bytes();

        let stream: Option<(i64, Option<Vec<u8>>)> = tx
            .query_row(
                "SELECT current_version, last_event_id
                 FROM aggregate_streams
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                params![CORRELATION_TYPE_TASK_RUN, taskrun_bytes],
                |row| Ok((row.get(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()
            .map_err(map_event_store_read_error)?;

        let (current_version, last_event_id_bytes) = match stream {
            Some((cv, lei)) => (cv as u64, lei),
            None => {
                return Err(EventStoreError::NotFound);
            }
        };

        let mut stmt = tx
            .prepare(
                "SELECT event_id, sequence, timestamp, schema_version,
                        causation_id, command_id, idempotency_key, actor,
                        payload, integrity_digest, correlation_id,
                        correlation_type, integrity_profile, global_position, sensitivity
                 FROM events
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2
                 ORDER BY sequence ASC",
            )
            .map_err(map_event_store_read_error)?;

        let event_rows = stmt
            .query_map(params![CORRELATION_TYPE_TASK_RUN, taskrun_bytes], |row| {
                let eid: Vec<u8> = row.get(0)?;
                let seq: i64 = row.get(1)?;
                let ts: i64 = row.get(2)?;
                let sv: i64 = row.get(3)?;
                let cid_opt: Option<Vec<u8>> = row.get(4)?;
                let cmd: Vec<u8> = row.get(5)?;
                let ikey: Vec<u8> = row.get(6)?;
                let act: Vec<u8> = row.get(7)?;
                let payload_bytes: Vec<u8> = row.get(8)?;
                let digest_bytes: Vec<u8> = row.get(9)?;
                let correlation_bytes: Vec<u8> = row.get(10)?;
                let correlation_type: i64 = row.get(11)?;
                let integrity_profile: i64 = row.get(12)?;
                let global_position: i64 = row.get(13)?;
                let sensitivity: i64 = row.get(14)?;
                Ok((
                    eid,
                    seq as u64,
                    ts,
                    sv as u32,
                    cid_opt,
                    cmd,
                    ikey,
                    act,
                    payload_bytes,
                    digest_bytes,
                    correlation_bytes,
                    correlation_type,
                    integrity_profile,
                    global_position,
                    sensitivity,
                ))
            })
            .map_err(map_event_store_read_error)?;

        let codec = TaskRunEventCodec;
        let mut events = Vec::new();

        for row in event_rows {
            let (
                eid_bytes,
                seq,
                ts_micros,
                schema_ver,
                causation_bytes,
                cmd_bytes,
                ikey_bytes,
                actor_bytes,
                payload_bytes,
                digest_bytes,
                correlation_bytes,
                correlation_type,
                integrity_profile,
                global_position,
                sensitivity_value,
            ) = row.map_err(map_event_store_read_error)?;

            let event_id = EventId::from_bytes(
                eid_bytes
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            let command_id = CommandId::from_bytes(
                cmd_bytes
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            let idempotency_key = runne_domain::id::IdempotencyKey::new(
                String::from_utf8_lossy(&ikey_bytes).as_ref(),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
            let actor = Actor::new(String::from_utf8_lossy(&actor_bytes).as_ref())
                .map_err(|_| EventStoreError::CorruptData)?;
            let causation_id = causation_bytes.map(|b| {
                let arr: [u8; 16] = b.try_into().unwrap_or([0u8; 16]);
                EventId::from_bytes(arr)
            });
            let integrity_digest = IntegrityDigest::from_bytes(
                digest_bytes
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            let payload = codec
                .decode(&payload_bytes)
                .map_err(|_| EventStoreError::CorruptData)?;
            let sensitivity = match sensitivity_value {
                0 => Sensitivity::Public,
                2 if matches!(&payload, TaskRunEvent::TaskRunSubmitted { .. }) => {
                    Sensitivity::Sensitive
                }
                _ => return Err(EventStoreError::CorruptData),
            };
            let aggregate_id = AggregateId::TaskRun(taskrun_id);
            if integrity_profile != INTEGRITY_PROFILE_V1 {
                return Err(EventStoreError::CorruptData);
            }
            let correlation_id = match StoredCorrelationType::from_i64(correlation_type)? {
                StoredCorrelationType::TaskRun => TaskRunId::from_bytes(
                    correlation_bytes
                        .try_into()
                        .map_err(|_| EventStoreError::CorruptData)?,
                ),
                StoredCorrelationType::Conversation => return Err(EventStoreError::CorruptData),
            };
            if correlation_id != taskrun_id {
                return Err(EventStoreError::CorruptData);
            }

            let envelope = EventEnvelope::from_parts(
                event_id,
                aggregate_id.clone(),
                AggregateId::TaskRun(correlation_id),
                causation_id,
                command_id,
                idempotency_key,
                schema_ver,
                actor,
                sensitivity,
                payload,
                seq,
                Timestamp::from_unix_micros(ts_micros),
                integrity_digest,
            );
            let expected_digest = compute_integrity_digest_with_global_position(
                &envelope,
                global_position,
                &payload_bytes,
            )
            .map_err(|_| EventStoreError::CorruptData)?;
            if envelope.integrity_digest() != &expected_digest {
                return Err(EventStoreError::CorruptData);
            }

            events.push(envelope);
        }

        let last_event_id = last_event_id_bytes.map(|b| {
            let arr: [u8; 16] = b.try_into().unwrap_or([0u8; 16]);
            EventId::from_bytes(arr)
        });
        drop(stmt);
        tx.commit().map_err(map_event_store_read_error)?;

        Ok(LoadedStream {
            events,
            current_version,
            last_event_id,
        })
    }
}

include!("events/effects.rs");
include!("events/effects_projection.rs");
