use super::{
    AppliedReplayEvent, LocalStore, OptionalExtension, ReplayApplyOutcome, ReplayStoreError,
    is_lower_hex_digest, params, read_database_generation, read_replay_state, sha256_lower_hex,
    validate_replay_scope,
};

impl LocalStore {
    /// Confirms that one replay event was already applied to the exact scope.
    ///
    /// # Errors
    ///
    /// Returns a typed integrity, identity, or storage error when the event
    /// cannot be proven to match the durable replay state.
    pub fn confirm_replay_event_applied(
        &self,
        event: &AppliedReplayEvent<'_>,
    ) -> Result<ReplayApplyOutcome, ReplayStoreError> {
        validate_replay_scope(event.scope)?;
        if event.event_id.is_empty() {
            return Err(ReplayStoreError::InvalidScope);
        }
        if event.cursor.is_empty() {
            return Err(ReplayStoreError::EmptyCursor);
        }
        if event.event_sequence == 0 {
            return Err(ReplayStoreError::NonContiguousSequence);
        }
        if !is_lower_hex_digest(event.event_digest)
            || sha256_lower_hex(event.event_bytes) != event.event_digest
        {
            return Err(ReplayStoreError::EventDigestMismatch);
        }
        read_replay_state(&self.connection, event.scope)?
            .ok_or(ReplayStoreError::EventIdentityConflict)?;
        let generation =
            i64::try_from(event.generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
        let event_sequence =
            i64::try_from(event.event_sequence).map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
        let stored: Option<(String, String, i64, i64, Vec<u8>, String)> = self
            .connection
            .query_row(
                "
                SELECT
                    binding_digest,
                    cursor,
                    generation,
                    event_sequence,
                    validated_event,
                    event_digest
                FROM event_journal
                WHERE runtime_authority = ?1
                  AND principal = ?2
                  AND lineage = ?3
                  AND scope = ?4
                  AND event_id = ?5
                ",
                params![
                    event.scope.runtime_authority,
                    event.scope.principal,
                    event.scope.lineage,
                    event.scope.scope,
                    event.event_id
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some(stored) = stored else {
            return Err(ReplayStoreError::EventIdentityConflict);
        };
        if stored.0 != event.scope.binding_digest
            || stored.1 != event.cursor
            || stored.2 != generation
            || stored.3 != event_sequence
            || stored.4 != event.event_bytes
            || stored.5 != event.event_digest
        {
            return Err(ReplayStoreError::EventIdentityConflict);
        }
        Ok(ReplayApplyOutcome::AlreadyApplied {
            database_generation: read_database_generation(&self.connection)?,
        })
    }
}
