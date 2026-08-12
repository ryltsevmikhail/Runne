use super::{
    Digest, LocalStore, ReplayCheckpoint, ReplayScopeKey, ReplayStoreError, Sha256,
    StoredConversationProjection, TransactionBehavior, params, read_replay_state,
    validate_replay_scope,
};

impl LocalStore {
    /// Reads the verified replay checkpoint for one stable scope.
    ///
    /// # Errors
    ///
    /// Returns a typed integrity or storage error when the scope or durable
    /// replay state cannot be verified.
    pub fn replay_checkpoint(
        &self,
        scope: &ReplayScopeKey,
    ) -> Result<Option<ReplayCheckpoint>, ReplayStoreError> {
        validate_replay_scope(scope)?;
        Ok(read_replay_state(&self.connection, scope)?.map(|state| state.checkpoint))
    }

    /// Reads the verified Conversation projection for one stable replay scope.
    ///
    /// # Errors
    ///
    /// Returns a typed integrity error for invalid JSON, a digest mismatch,
    /// binding mismatch or non-contiguous stored state.
    pub fn conversation_projection(
        &self,
        scope: &ReplayScopeKey,
    ) -> Result<Option<StoredConversationProjection>, ReplayStoreError> {
        validate_replay_scope(scope)?;
        Ok(read_replay_state(&self.connection, scope)?.map(|state| state.projection))
    }

    /// Atomically clears one affected replay scope before an explicit
    /// authoritative rebuild from the retained floor.
    ///
    /// # Errors
    ///
    /// Returns a typed validation or storage error without partially deleting
    /// journal, projection, or checkpoint state.
    pub fn reset_replay_scope(&mut self, scope: &ReplayScopeKey) -> Result<bool, ReplayStoreError> {
        if self.security.is_some() {
            return Err(ReplayStoreError::AnchoredAdmissionRequired);
        }
        validate_replay_scope(scope)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = transaction.query_row(
            "
            SELECT
                (SELECT COUNT(*) FROM event_journal
                 WHERE runtime_authority = ?1 AND principal = ?2
                   AND lineage = ?3 AND scope = ?4)
              + (SELECT COUNT(*) FROM projections
                 WHERE runtime_authority = ?1 AND principal = ?2
                   AND lineage = ?3 AND scope = ?4)
              + (SELECT COUNT(*) FROM replay_cursors
                 WHERE runtime_authority = ?1 AND principal = ?2
                   AND lineage = ?3 AND scope = ?4)
            ",
            params![
                scope.runtime_authority,
                scope.principal,
                scope.lineage,
                scope.scope
            ],
            |row| row.get(0),
        )?;
        if count == 0 {
            transaction.commit()?;
            return Ok(false);
        }
        for table in ["event_journal", "projections", "replay_cursors"] {
            transaction.execute(
                &format!(
                    "DELETE FROM {table}
                     WHERE runtime_authority = ?1 AND principal = ?2
                       AND lineage = ?3 AND scope = ?4"
                ),
                params![
                    scope.runtime_authority,
                    scope.principal,
                    scope.lineage,
                    scope.scope
                ],
            )?;
        }
        let mut hasher = Sha256::new();
        hasher.update(b"gocode/local-store/replay-scope-reset/v1\0");
        for value in [
            scope.runtime_authority.as_bytes(),
            scope.principal.as_bytes(),
            scope.lineage.as_bytes(),
            scope.scope.as_bytes(),
            scope.binding_digest.as_bytes(),
        ] {
            hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(value);
        }
        transaction.execute("UPDATE meta SET db_generation=db_generation+1,last_transaction_digest=?1,commit_marker=1 WHERE singleton=1", params![format!("{:x}", hasher.finalize())])?;
        transaction.commit()?;
        Ok(true)
    }
}
