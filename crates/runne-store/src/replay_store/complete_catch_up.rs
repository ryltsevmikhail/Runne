impl ReplayStore {
    #[allow(clippy::too_many_arguments)]
    async fn complete_catch_up_impl(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        server_secret: &[u8; 32],
        authorization_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Option<ReplayEvent>), ReplayError> {
        let conn = Arc::clone(&self.conn);
        let session_id = *session_id;
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;
        let server_secret = *server_secret;

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
            if session.state == ReplayState::CatchUpComplete
                && session.catch_up_completion.is_some()
            {
                authorization_guard.inspect_ack(&session)?;
                let last_acked_event = read_last_acked_event(&conn, &session)?;
                return Ok((session, last_acked_event));
            }
            if session.state != ReplayState::CatchingUp {
                return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
            }

            if session.next_page_position.is_some() {
                return Err(ReplayError::NotAcknowledged);
            }
            let last_in_scope: Option<i64> = conn
                .query_row(
                    "SELECT MAX(global_position)
                     FROM events
                     WHERE aggregate_type = ?1
                       AND aggregate_id = ?2
                       AND global_position <= ?3",
                    params![
                        session.aggregate_type,
                        session.aggregate_id.as_slice(),
                        session.high_water_position
                    ],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    ReplayError::Storage(format!("read scoped high water: {error}"))
                })?;
            match (last_in_scope, session.last_delivered_position) {
                (Some(expected), Some(last_delivered)) if last_delivered != expected => {
                    return Err(ReplayError::NotAcknowledged);
                }
                (Some(expected), Some(last_delivered))
                    if session.last_acked_position != Some(last_delivered)
                        || last_delivered != expected =>
                {
                    return Err(ReplayError::NotAcknowledged);
                }
                (Some(_), None) | (None, Some(_)) => return Err(ReplayError::NotAcknowledged),
                (Some(_), Some(_)) | (None, None) => {}
            }
            let proof = build_catch_up_completion_proof(&session, &server_secret);

            let affected = authorization_guard.mutate_ack(&session, &mut || {
                conn.execute(
                    "UPDATE _replay_subscriptions
                          SET state = 'catch_up_complete',
                          catch_up_completion = ?1
                     WHERE session_id = ?2
                       AND state = 'catching_up'
                       AND principal_id = ?3
                       AND session_generation = ?4
                       AND authority_id = ?5
                       AND authorization_epoch = ?6",
                    params![
                        proof.as_slice(),
                        session_id.as_slice(),
                        principal_id.as_str(),
                        generation,
                        authority_id.as_slice(),
                        epoch,
                    ],
                )
                .map_err(|e| ReplayError::Storage(format!("update: {}", e)))
            })?;

            if affected != 1 {
                return Err(ReplayError::Integrity(format!(
                    "expected 1 row affected, got {}",
                    affected
                )));
            }

            // Re-read the session
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

            let last_acked_event = read_last_acked_event(&conn, &session)?;
            Ok((session, last_acked_event))
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }
}
