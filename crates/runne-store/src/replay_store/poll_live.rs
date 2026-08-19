impl ReplayStore {
   async fn poll_live_impl(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        let conn = Arc::clone(&self.conn);
        let session_id = *session_id;
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;

        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|e| ReplayError::Storage(format!("lock poisoned: {}", e)))?;

            // Read session and validate auth
            let session: ReplaySession = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .optional()
                .map_err(|e| ReplayError::Storage(format!("read session: {}", e)))?
                .ok_or(ReplayError::SessionNotFound)?;

            validate_auth(&session, &principal_id, generation, &authority_id, epoch)?;

            if session.state != ReplayState::Live {
                return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
            }

            let expected_first = match session.last_delivered_position {
                Some(position) => {
                    let event = read_session_event_at(
                        &conn,
                        &session,
                        position,
                        "read previous live replay event",
                    )?
                    .ok_or_else(|| {
                        ReplayError::Integrity(
                            "previously delivered live replay event is unavailable".to_owned(),
                        )
                    })?;
                    next_sequence_after(&event)?
                }
                None => 1,
            };

            // Continue after the most recent event delivered by this live
            // lane, while never moving behind the catch-up high-water mark.
            let cursor = session
                .last_delivered_position
                .unwrap_or(session.high_water_position)
                .max(session.high_water_position);

            let mut stmt = conn
                .prepare(
                    "SELECT event_id, aggregate_type, aggregate_id, sequence,
                            global_position, timestamp, sensitivity, schema_version,
                            causation_id, command_id, idempotency_key, actor,
                            payload, integrity_digest, correlation_id,
                            correlation_type, integrity_profile
                     FROM events
                     WHERE aggregate_type = ?1 AND aggregate_id = ?2
                       AND global_position > ?3
                     ORDER BY global_position
                     LIMIT 100",
                )
                .map_err(|e| ReplayError::Storage(format!("prepare: {}", e)))?;

            let aggregate_type = session.aggregate_type;
            let aggregate_id = session.aggregate_id;

            let mut events = stmt
                .query_map(
                    params![aggregate_type, aggregate_id.as_slice(), cursor],
                    read_replay_event,
                )
                .map_err(|e| ReplayError::Storage(format!("query events: {}", e)))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| replay_row_error("collect events", error))?;

            validate_contiguous_sequence(&events, expected_first)?;

            let mut candidate = session.clone();
            let mut authorized_prefix_len = 0;
            for (index, event) in events.iter().enumerate() {
                candidate.last_delivered_position = Some(event.global_position);
                match delivery_guard.inspect_event(&candidate, event) {
                    Ok(()) => authorized_prefix_len = index + 1,
                    Err(ReplayError::SensitivityDenied) if authorized_prefix_len > 0 => break,
                    Err(error) => return Err(error),
                }
            }
            events.truncate(authorized_prefix_len);
            candidate.last_delivered_position = events
                .last()
                .map(|event| event.global_position)
                .or(session.last_delivered_position);
            delivery_guard.inspect(&candidate, &events)?;

            // Commit progress only after the transport has classified the
            // exact serialized live deliveries.
            if let Some(last_event) = events.last() {
                conn.execute(
                    "UPDATE _replay_subscriptions
                     SET last_delivered_position = ?1
                     WHERE session_id = ?2",
                    params![last_event.global_position, session_id.as_slice()],
                )
                .map_err(|e| ReplayError::Storage(format!("update cursors: {}", e)))?;
            }

            let session = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .map_err(|error| ReplayError::Storage(format!("re-read live session: {error}")))?;

            Ok((session, events))
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }
}
