use super::{
    LocalStore, OptionalExtension, ReplayApplyOutcome, ReplayScopeKey, ReplayStoreError,
    ReplayTransition, StoredJournalTransition, params, read_database_generation, read_replay_state,
    validate_expected_transition, validate_replay_scope, validate_replay_transition_payload,
    validate_replay_transition_shape,
};
use gocode_secure_store::SecureStore;

impl LocalStore {
    /// Applies one replay transition through the connected security anchor.
    #[allow(clippy::too_many_lines)]
    pub fn apply_anchored_replay_transition(
        &mut self,
        secure: &dyn SecureStore,
        transition: &ReplayTransition<'_>,
    ) -> Result<ReplayApplyOutcome, ReplayStoreError> {
        validate_replay_transition_shape(transition)?;
        if let Some(shadow) =
            crate::replay_shadow::selected_shadow(&self.connection, transition.scope)?
        {
            return self
                .apply_selected_anchored_shadow_replay_transition(secure, &shadow, transition);
        }
        let generation = i64::try_from(transition.generation)
            .map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
        let event_sequence = i64::try_from(transition.event_sequence)
            .map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
        let projection_revision = i64::try_from(transition.projection_revision)
            .map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
        let scope = transition.scope;
        let (outcome, _) = self.commit_anchored_security_write(secure, |transaction| {
            let selected: Option<(String, Option<String>)> = transaction.query_row("SELECT selector,shadow_id FROM replay_active_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
            if selected.is_some_and(|(selector, shadow)| selector != "legacy" || shadow.is_some()) {
                return Err(ReplayStoreError::PromotionConflict);
            }
            transaction.execute("INSERT INTO replay_active_generations(runtime_authority,principal,lineage,scope,selector,shadow_id) VALUES(?1,?2,?3,?4,'legacy',NULL) ON CONFLICT(runtime_authority,principal,lineage,scope) DO NOTHING", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope])?;
            let existing: Option<StoredJournalTransition> = transaction
                .query_row(
                    "SELECT binding_digest,cursor,generation,event_sequence,validated_event,event_digest,projection_revision,projection_digest,projected_payload FROM event_journal WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND event_id=?5",
                    params![scope.runtime_authority, scope.principal, scope.lineage, scope.scope, transition.event_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?)),
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing.0 != scope.binding_digest {
                    return Err(ReplayStoreError::BindingMismatch);
                }
                if existing.1 != transition.cursor
                    || existing.2 != generation
                    || existing.3 != event_sequence
                    || existing.4 != transition.event_bytes
                    || existing.5 != transition.event_digest
                    || existing.6 != projection_revision
                    || existing.7 != transition.projection_digest
                    || existing.8 != transition.projection_bytes
                {
                    return Err(ReplayStoreError::EventIdentityConflict);
                }
                read_replay_state(transaction, scope)?
                    .ok_or(ReplayStoreError::NonContiguousRevision)?;
                return Ok((
                    ReplayApplyOutcome::AlreadyApplied {
                        database_generation: read_database_generation(transaction)?,
                    },
                    false,
                ));
            }
            validate_replay_transition_payload(transaction, transition)?;
            let current = read_replay_state(transaction, scope)?;
            validate_expected_transition(current.as_ref(), transition)?;
            transaction.execute(
                "INSERT INTO event_journal (runtime_authority,principal,lineage,scope,binding_digest,event_id,cursor,generation,event_sequence,validated_event,event_digest,projection_revision,projection_digest,projected_payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![scope.runtime_authority, scope.principal, scope.lineage, scope.scope, scope.binding_digest, transition.event_id, transition.cursor, generation, event_sequence, transition.event_bytes, transition.event_digest, projection_revision, transition.projection_digest, transition.projection_bytes],
            )?;
            transaction.execute(
                "INSERT INTO projections (runtime_authority,principal,lineage,scope,binding_digest,projection_revision,projection_digest,event_sequence,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(runtime_authority,principal,lineage,scope) DO UPDATE SET binding_digest=excluded.binding_digest,projection_revision=excluded.projection_revision,projection_digest=excluded.projection_digest,event_sequence=excluded.event_sequence,payload=excluded.payload",
                params![scope.runtime_authority, scope.principal, scope.lineage, scope.scope, scope.binding_digest, projection_revision, transition.projection_digest, event_sequence, transition.projection_bytes],
            )?;
            transaction.execute(
                "INSERT INTO replay_cursors (runtime_authority,principal,lineage,scope,binding_digest,generation,applied_cursor,event_sequence,projection_revision,projection_digest) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(runtime_authority,principal,lineage,scope) DO UPDATE SET binding_digest=excluded.binding_digest,generation=excluded.generation,applied_cursor=excluded.applied_cursor,event_sequence=excluded.event_sequence,projection_revision=excluded.projection_revision,projection_digest=excluded.projection_digest",
                params![scope.runtime_authority, scope.principal, scope.lineage, scope.scope, scope.binding_digest, generation, transition.cursor, event_sequence, projection_revision, transition.projection_digest],
            )?;
            Ok((
                ReplayApplyOutcome::Applied { database_generation: 0 },
                true,
            ))
        })?;
        match outcome {
            ReplayApplyOutcome::Applied { .. } => Ok(ReplayApplyOutcome::Applied {
                database_generation: read_database_generation(&self.connection)?,
            }),
            replay @ ReplayApplyOutcome::AlreadyApplied { .. } => Ok(replay),
        }
    }

    /// Resets a replay scope through the connected security anchor.
    pub fn reset_anchored_replay_scope(
        &mut self,
        secure: &dyn SecureStore,
        scope: &ReplayScopeKey,
    ) -> Result<bool, ReplayStoreError> {
        validate_replay_scope(scope)?;
        let (changed, _) = self.commit_anchored_security_write(secure, |transaction| {
            let selected: Option<(String, Option<String>)> = transaction.query_row("SELECT selector,shadow_id FROM replay_active_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
            let shadow_state: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 UNION ALL SELECT 1 FROM replay_promotion_pending WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4)",
                params![scope.runtime_authority, scope.principal, scope.lineage, scope.scope],
                |row| row.get(0),
            )?;
            if shadow_state {
                return Err(ReplayStoreError::PromotionConflict);
            }
            if selected.is_some_and(|(selector, shadow)| selector != "legacy" || shadow.is_some()) {
                return Err(ReplayStoreError::PromotionConflict);
            }
            let count: i64 = transaction.query_row(
                "SELECT (SELECT COUNT(*) FROM event_journal WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4)+(SELECT COUNT(*) FROM projections WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4)+(SELECT COUNT(*) FROM replay_cursors WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4)",
                params![scope.runtime_authority, scope.principal, scope.lineage, scope.scope],
                |row| row.get(0),
            )?;
            if count == 0 {
                return Ok::<_, ReplayStoreError>((false, false));
            }
            for table in ["event_journal", "projections", "replay_cursors"] {
                transaction.execute(
                    &format!("DELETE FROM {table} WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4"),
                    params![scope.runtime_authority, scope.principal, scope.lineage, scope.scope],
                )?;
            }
            Ok::<_, ReplayStoreError>((true, true))
        })?;
        Ok(changed)
    }
}
