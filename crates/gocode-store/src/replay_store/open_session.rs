impl ReplayStore {
    #[allow(clippy::too_many_arguments)]
    async fn open_session_impl(
        &self,
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        authorization_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
        from_cursor: Option<&ReplayCursor>,
        lineage_id: &EventLogLineageId,
        server_secret: &[u8; 32],
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<ReplayOpenResult, ReplayError> {
        let conn = Arc::clone(&self.conn);
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;
        let aggregate_id_copy = *aggregate_id;
        let from_cursor = from_cursor.cloned();
        let from_position = from_cursor.as_ref().map(|cursor| cursor.global_position);
        let lineage_id = *lineage_id;
        let server_secret = *server_secret;

        tokio::task::spawn_blocking(move || {
            let mut conn = conn
                .lock()
                .map_err(|e| ReplayError::Storage(format!("lock poisoned: {}", e)))?;

            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| ReplayError::Storage(format!("transaction: {}", e)))?;

            let inventory = retained_inventory(&tx)?;
            let retention_manifest =
                retention_manifest_for_events(&inventory.events, lineage_id, &server_secret)?;
            let scope = ReplayScope::Aggregate {
                aggregate_type: u8::try_from(aggregate_type).map_err(|_| {
                    ReplayError::Integrity("invalid replay aggregate type".to_owned())
                })?,
                aggregate_id: aggregate_id_copy,
            };
            let gap = match (
                from_position,
                retention_manifest.retained_floor(),
                inventory.interior_gap,
            ) {
                (Some(position), Some(floor), _) if position < floor => {
                    Some((position, floor.saturating_sub(1)))
                }
                (_, _, Some(bounds)) => Some(bounds),
                _ => None,
            };
            if let Some((missing_start, missing_end)) = gap {
                let floor_event = inventory
                    .events
                    .iter()
                    .find(|event| {
                        event.aggregate_type == aggregate_type
                            && event.aggregate_id == aggregate_id_copy
                    })
                    .cloned();
                return Ok(ReplayOpenResult::RetentionGap {
                    floor_event,
                    gap_range_ref: build_gap_range_ref(
                        &lineage_id,
                        retention_manifest.retention_generation(),
                        missing_start,
                        missing_end,
                        &scope,
                        authorization_epoch,
                        &server_secret,
                    ),
                });
            }

            // Capture current high-water mark
            let high_water: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(global_position), 0) FROM events",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| ReplayError::Storage(format!("high water: {}", e)))?;
            let stream_version: Option<i64> = tx
                .query_row(
                    "SELECT current_version
                     FROM aggregate_streams
                     WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                    params![aggregate_type, aggregate_id_copy.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| {
                    ReplayError::Storage(format!("read replay stream version: {error}"))
                })?;
            let last_sequence: Option<i64> = tx
                .query_row(
                    "SELECT MAX(sequence)
                     FROM events
                     WHERE aggregate_type = ?1
                       AND aggregate_id = ?2
                       AND global_position <= ?3",
                    params![aggregate_type, aggregate_id_copy.as_slice(), high_water],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    ReplayError::Storage(format!("read replay stream sequence: {error}"))
                })?;
            match (stream_version, last_sequence) {
                (None, None) | (Some(0), None) => {}
                (Some(version), Some(sequence))
                    if version > 0 && sequence > 0 && version == sequence => {}
                _ => {
                    return Err(ReplayError::Integrity(
                        "replay stream head does not match retained events".to_owned(),
                    ));
                }
            }
            if let Some(cursor) = &from_cursor {
                validate_cursor_event(&tx, cursor, aggregate_type, &aggregate_id_copy)?;
            }

            // Generate session ID
            let session_id = Self::generate_session_id();

            // Build high_water_ref
            let high_water_ref = build_high_water_ref(
                &authority_id,
                retention_manifest.retained_floor(),
                high_water,
                &server_secret,
                &session_id,
            );

            // Read one look-ahead row so an exactly full page is not mistaken
            // for an unfinished page.
            let mut events = {
                let mut stmt = tx
                    .prepare(
                        "SELECT event_id, aggregate_type, aggregate_id, sequence,
                                global_position, timestamp, sensitivity, schema_version,
                                causation_id, command_id, idempotency_key, actor,
                                payload, integrity_digest, correlation_id,
                                correlation_type, integrity_profile
                         FROM events
                         WHERE aggregate_type = ?1 AND aggregate_id = ?2
                           AND global_position >= ?3
                           AND global_position <= ?4
                         ORDER BY global_position
                         LIMIT 101",
                    )
                    .map_err(|e| ReplayError::Storage(format!("prepare: {}", e)))?;

                stmt.query_map(
                    params![
                        aggregate_type,
                        aggregate_id_copy.as_slice(),
                        from_position.unwrap_or(0),
                        high_water,
                    ],
                    read_replay_event,
                )
                .map_err(|e| ReplayError::Storage(format!("query events: {}", e)))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| replay_row_error("collect events", error))?
            };
            validate_contiguous_sequence(
                &events,
                from_cursor.as_ref().map_or(1, |cursor| cursor.sequence),
            )?;

            // Compute initial cursors from first page
            let has_more_after_selection = events.len() > 100;
            events.truncate(100);
            let selected_len = events.len();
            let mut authorized_prefix_len = 0;
            let mut prefix_candidate = ReplaySession {
                session_id,
                principal_id: principal_id.clone(),
                session_generation,
                authority_id,
                authorization_epoch,
                aggregate_type,
                aggregate_id: aggregate_id_copy,
                retained_floor: retention_manifest.retained_floor(),
                retention_generation: i64::try_from(retention_manifest.retention_generation())
                    .map_err(|_| {
                        ReplayError::Integrity("retention generation overflow".to_owned())
                    })?,
                high_water_position: high_water,
                next_page_position: None,
                last_delivered_position: None,
                last_acked_position: None,
                state: ReplayState::CatchingUp,
                high_water_ref: high_water_ref.clone(),
                catch_up_completion: None,
                live_delivery_id: None,
                created_at: String::new(),
            };
            for (index, event) in events.iter().enumerate() {
                prefix_candidate.last_delivered_position = Some(event.global_position);
                prefix_candidate.next_page_position =
                    if index + 1 < selected_len || has_more_after_selection {
                        Some(event.global_position.checked_add(1).ok_or_else(|| {
                            ReplayError::Integrity(
                                "global position overflow while opening replay session".to_string(),
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
            let last_delivered = events.last().map(|e| e.global_position);
            let next_page = if has_more {
                Some(
                    last_delivered
                        .and_then(|position| position.checked_add(1))
                        .ok_or_else(|| {
                            ReplayError::Integrity(
                                "global position overflow while opening replay session".to_string(),
                            )
                        })?,
                )
            } else {
                None
            };
            let candidate = ReplaySession {
                next_page_position: next_page,
                last_delivered_position: last_delivered,
                ..prefix_candidate
            };
            delivery_guard.inspect(&candidate, &events)?;

            // Insert session row with computed cursors
            tx.execute(
                "INSERT INTO _replay_subscriptions (
                    session_id, principal_id, session_generation, authority_id,
                    authorization_epoch, aggregate_type, aggregate_id,
                    retained_floor, retention_generation, high_water_position,
                    next_page_position, last_delivered_position,
                    state, high_water_ref, created_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                    ?10, ?11, ?12,
                    'catching_up', ?13, datetime('now')
                )",
                params![
                    session_id.as_slice(),
                    principal_id.as_str(),
                    session_generation,
                    authority_id.as_slice(),
                    authorization_epoch,
                    aggregate_type,
                    aggregate_id_copy.as_slice(),
                    retention_manifest.retained_floor(),
                    i64::try_from(retention_manifest.retention_generation()).map_err(|_| {
                        ReplayError::Integrity("retention generation overflow".to_owned())
                    })?,
                    high_water,
                    next_page,
                    last_delivered,
                    high_water_ref.as_slice(),
                ],
            )
            .map_err(|e| ReplayError::Storage(format!("insert session: {}", e)))?;

            tx.commit()
                .map_err(|e| ReplayError::Storage(format!("commit: {}", e)))?;

            // Re-read the session to get all fields
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
                .map_err(|e| ReplayError::Storage(format!("re-read session: {}", e)))?;

            Ok(ReplayOpenResult::Opened { session, events })
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }
}
