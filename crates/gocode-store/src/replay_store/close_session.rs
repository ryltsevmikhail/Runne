impl ReplayStore {
   async fn close_session_impl(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<(), ReplayError> {
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

            // Allow close from CatchUpComplete or Live
            match session.state {
                ReplayState::CatchUpComplete | ReplayState::Live => {}
                _ => {
                    return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
                }
            }

            let affected = conn
                .execute(
                    "UPDATE _replay_subscriptions
                     SET state = 'closed'
                     WHERE session_id = ?1
                       AND state IN ('catch_up_complete', 'live')
                       AND principal_id = ?2
                       AND session_generation = ?3
                       AND authority_id = ?4
                       AND authorization_epoch = ?5",
                    params![
                        session_id.as_slice(),
                        principal_id.as_str(),
                        generation,
                        authority_id.as_slice(),
                        epoch,
                    ],
                )
                .map_err(|e| ReplayError::Storage(format!("close: {}", e)))?;

            if affected != 1 {
                return Err(ReplayError::InvalidState(
                    "session was already closed or state changed".to_string(),
                ));
            }

            Ok(())
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }
}
