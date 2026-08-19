impl ReplayStore {
    #[allow(clippy::too_many_arguments)]
    async fn acknowledge_impl(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        cursor: &ReplayCursor,
        authorization_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(), ReplayError> {
        let conn = Arc::clone(&self.conn);
        let session_id = *session_id;
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;
        let cursor = cursor.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|e| ReplayError::Storage(format!("lock poisoned: {e}")))?;
            let session: ReplaySession = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                        authorization_epoch, aggregate_type, aggregate_id,
                        retained_floor, retention_generation, high_water_position,
                        next_page_position, last_delivered_position, last_acked_position,
                        state, high_water_ref, catch_up_completion, live_delivery_id,
                        created_at FROM _replay_subscriptions WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .optional()
                .map_err(|e| ReplayError::Storage(format!("read session: {e}")))?
                .ok_or(ReplayError::SessionNotFound)?;
            validate_auth(&session, &principal_id, generation, &authority_id, epoch)?;
            if !matches!(session.state, ReplayState::CatchingUp | ReplayState::Live) {
                return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
            }
            let position = cursor.global_position;
            let last_delivered = session
                .last_delivered_position
                .ok_or(ReplayError::NotAcknowledged)?;
            if position > last_delivered {
                return Err(ReplayError::NotAcknowledged);
            }
            validate_cursor_event(
                &conn,
                &cursor,
                session.aggregate_type,
                &session.aggregate_id,
            )?;
            match session.last_acked_position {
                Some(last_acked) if position < last_acked => {
                    return Err(ReplayError::AlreadyAcknowledged);
                }
                Some(last_acked) if position == last_acked => return Ok(()),
                _ => {}
            }
            let affected = authorization_guard.mutate_ack(&session, &mut || {
                conn.execute(
                    "UPDATE _replay_subscriptions
                     SET last_acked_position = ?1
                     WHERE session_id = ?2",
                    params![position, session_id.as_slice()],
                )
                .map_err(|e| ReplayError::Storage(format!("acknowledge: {e}")))
            })?;
            if affected != 1 {
                return Err(ReplayError::Integrity(format!(
                    "expected 1 row affected, got {affected}"
                )));
            }
            Ok(())
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {e}")))?
    }
}
