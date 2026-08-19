impl ReplayStore {
    #[allow(clippy::too_many_arguments)]
    async fn read_page_impl(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        limit: usize,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        if limit == 0 {
            return Err(ReplayError::Integrity(
                "replay page limit must be greater than zero".to_string(),
            ));
        }
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

            if session.state != ReplayState::CatchingUp {
                return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
            }

            let expected_first = match session.last_delivered_position {
                Some(position) => {
                    let event = read_session_event_at(
                        &conn,
                        &session,
                        position,
                        "read previous replay page event",
                    )?
                    .ok_or_else(|| {
                        ReplayError::Integrity(
                            "previously delivered replay event is unavailable".to_owned(),
                        )
                    })?;
                    next_sequence_after(&event)?
                }
                None => 1,
            };

            // Determine the cursor position to read after
            let cursor = session.last_delivered_position.unwrap_or(-1);

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
                        AND global_position <= ?4
                      ORDER BY global_position
                      LIMIT ?5",
                )
                .map_err(|e| ReplayError::Storage(format!("prepare: {}", e)))?;

            let aggregate_type = session.aggregate_type;
            let aggregate_id = session.aggregate_id;

            let fetch_limit = limit
                .checked_add(1)
                .ok_or_else(|| ReplayError::Integrity("replay page limit overflow".to_string()))?;
            let fetch_limit = i64::try_from(fetch_limit)
                .map_err(|_| ReplayError::Integrity("replay page limit overflow".to_string()))?;
            let mut events = stmt
                .query_map(
                    params![
                        aggregate_type,
                        aggregate_id.as_slice(),
                        cursor,
                        session.high_water_position,
                        fetch_limit
                    ],
                    read_replay_event,
                )
                .map_err(|e| ReplayError::Storage(format!("query events: {}", e)))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| replay_row_error("collect events", error))?;

            if session.next_page_position.is_some() && events.is_empty() {
                return Err(ReplayError::Integrity(
                    "replay catch-up suffix is unavailable".to_owned(),
                ));
            }
            validate_contiguous_sequence(&events, expected_first)?;

            let has_more_after_selection = events.len() > limit;
            events.truncate(limit);
            let selected_len = events.len();
            let mut authorized_prefix_len = 0;
            let mut prefix_candidate = session.clone();
            for (index, event) in events.iter().enumerate() {
                prefix_candidate.last_delivered_position = Some(event.global_position);
                prefix_candidate.next_page_position =
                    if index + 1 < selected_len || has_more_after_selection {
                        Some(event.global_position.checked_add(1).ok_or_else(|| {
                            ReplayError::Integrity(
                                "global position overflow while reading replay page".to_string(),
                            )
                        })?)
                    } else {
                        None
                    };
                match delivery_guard.inspect_event(&prefix_candidate, event) {
                    Ok(()) => authorized_prefix_len = index + 1,
                    Err(ReplayError::SensitivityDenied) if authorized_prefix_len > 0 => break,
                    Err(error) => return Err(error),
                }
            }
            events.truncate(authorized_prefix_len);
            let has_more = has_more_after_selection || authorized_prefix_len < selected_len;

            let next_page = match events.last() {
                Some(last_event) if has_more => {
                    Some(last_event.global_position.checked_add(1).ok_or_else(|| {
                        ReplayError::Integrity(
                            "global position overflow while reading replay page".to_string(),
                        )
                    })?)
                }
                Some(_) => None,
                None => session.next_page_position,
            };
            let mut candidate = session.clone();
            if let Some(last_event) = events.last() {
                candidate.last_delivered_position = Some(last_event.global_position);
                candidate.next_page_position = next_page;
            }
            delivery_guard.inspect(&candidate, &events)?;

            // Commit cursors only after the transport has classified the exact
            // serialized delivery.
            if let Some(last_event) = events.last() {
                conn.execute(
                    "UPDATE _replay_subscriptions
                     SET last_delivered_position = ?1,
                         next_page_position = ?2
                     WHERE session_id = ?3",
                    params![last_event.global_position, next_page, session_id.as_slice(),],
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
                .map_err(|error| ReplayError::Storage(format!("re-read paged session: {error}")))?;

            Ok((session, events))
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }
}
