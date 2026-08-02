impl ReplayStore {
   async fn continue_live_impl(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        authorization_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<ReplaySession, ReplayError> {
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
            if session.state != ReplayState::CatchUpComplete {
                return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
            }

            let mut live_delivery_id = [0u8; 16];
            OsRng.fill_bytes(&mut live_delivery_id);

            // Generate the delivery identity first, then publish Live in one
            // durable CAS. No restart can observe an intermediate activation.
            let affected = authorization_guard.mutate_ack(&session, &mut || {
                conn.execute(
                    "UPDATE _replay_subscriptions
                     SET state = 'live',
                         live_delivery_id = ?1
                     WHERE session_id = ?2
                       AND state = 'catch_up_complete'
                       AND principal_id = ?3
                       AND session_generation = ?4
                       AND authority_id = ?5
                       AND authorization_epoch = ?6",
                    params![
                        live_delivery_id.as_slice(),
                        session_id.as_slice(),
                        principal_id.as_str(),
                        generation,
                        authority_id.as_slice(),
                        epoch,
                    ],
                )
                .map_err(|e| ReplayError::Storage(format!("activate live: {}", e)))
            })?;

            if affected != 1 {
                return Err(ReplayError::InvalidState(
                    "another activator already claimed this session".to_string(),
                ));
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

            Ok(session)
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }
}
