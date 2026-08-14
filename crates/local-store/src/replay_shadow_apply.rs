use super::{
    LocalStore, OptionalExtension, ReplayApplyOutcome, ReplayCheckpoint, ReplayScopeKey,
    ReplayStoreError, ReplayTransition, ShadowReplayId, params, read_database_generation,
    validate_replay_transition_payload, validate_replay_transition_shape,
};
use gocode_secure_store::SecureStore;

impl LocalStore {
    /// Authenticates and reads the current checkpoint of an unselected shadow.
    ///
    /// # Errors
    ///
    /// Returns an error when the shadow is not the exact bound generation or
    /// its protected anchor cannot be read.
    pub fn authenticated_shadow_replay_checkpoint(
        &mut self,
        secure: &dyn SecureStore,
        scope: &ReplayScopeKey,
        shadow: &ShadowReplayId,
    ) -> Result<Option<ReplayCheckpoint>, ReplayStoreError> {
        self.authenticated_replay_read(secure, |transaction| {
            require_shadow_writable(transaction, scope, shadow, false)?;
            shadow_checkpoint_for_transition(transaction, scope, shadow)
        })
    }

    /// Applies an authenticated suffix event to one isolated shadow generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the suffix does not extend the selected shadow
    /// exactly or cannot be anchored.
    pub fn apply_anchored_shadow_replay_transition(
        &mut self,
        secure: &dyn SecureStore,
        shadow: &ShadowReplayId,
        transition: &ReplayTransition<'_>,
    ) -> Result<ReplayApplyOutcome, ReplayStoreError> {
        self.apply_shadow_replay_transition(secure, shadow, transition, false)
    }

    pub(crate) fn apply_selected_anchored_shadow_replay_transition(
        &mut self,
        secure: &dyn SecureStore,
        shadow: &ShadowReplayId,
        transition: &ReplayTransition<'_>,
    ) -> Result<ReplayApplyOutcome, ReplayStoreError> {
        self.apply_shadow_replay_transition(secure, shadow, transition, true)
    }

    fn apply_shadow_replay_transition(
        &mut self,
        secure: &dyn SecureStore,
        shadow: &ShadowReplayId,
        transition: &ReplayTransition<'_>,
        require_selected: bool,
    ) -> Result<ReplayApplyOutcome, ReplayStoreError> {
        validate_replay_transition_shape(transition)?;
        let scope = transition.scope;
        let (outcome, _) = self.commit_anchored_security_write(secure, |tx| {
            require_shadow_writable(tx, scope, shadow, require_selected)?;
            validate_replay_transition_payload(tx, transition)?;
            let existing: Option<ShadowEvent> = tx
                .query_row(
                    "SELECT cursor,generation,event_sequence,event_payload,event_digest,projection_revision,projection_digest,projection_payload FROM replay_shadow_events WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5 AND event_id=?6",
                    params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0,transition.event_id],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
                )
                .optional()?;
            if let Some(event) = existing {
                return exact_event(&event, transition).then_some((
                    ReplayApplyOutcome::AlreadyApplied {
                        database_generation: read_database_generation(tx)?,
                    },
                    false,
                )).ok_or(ReplayStoreError::EventIdentityConflict);
            }
            let current = shadow_checkpoint_for_transition(tx, scope, shadow)?;
            validate_shadow_transition(current.as_ref(), transition, tx, scope, shadow)?;
            let sequence = i64::try_from(transition.event_sequence)
                .map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
            let generation = i64::try_from(transition.generation)
                .map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
            let revision = i64::try_from(transition.projection_revision)
                .map_err(|_| ReplayStoreError::IntegerOutOfRange)?;
            tx.execute(
                "INSERT INTO replay_shadow_events VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0,sequence,transition.event_id,transition.cursor,generation,transition.event_bytes,transition.event_digest,revision,transition.projection_digest,transition.projection_bytes],
            )?;
            tx.execute(
                "UPDATE replay_shadow_generations SET projection_payload=?6,projection_digest=?7,projection_revision=?8,cursor=?9,generation=?10,event_sequence=?11 WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5",
                params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0,transition.projection_bytes,transition.projection_digest,revision,transition.cursor,generation,sequence],
            )?;
            Ok((ReplayApplyOutcome::Applied { database_generation: 0 }, true))
        })?;
        Ok(match outcome {
            ReplayApplyOutcome::Applied { .. } => ReplayApplyOutcome::Applied {
                database_generation: read_database_generation(&self.connection)?,
            },
            other @ ReplayApplyOutcome::AlreadyApplied { .. } => other,
        })
    }
}

type ShadowEvent = (String, i64, i64, Vec<u8>, String, i64, String, Vec<u8>);

fn require_shadow_writable(
    tx: &rusqlite::Transaction<'_>,
    scope: &ReplayScopeKey,
    shadow: &ShadowReplayId,
    require_selected: bool,
) -> Result<(), ReplayStoreError> {
    let pending: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM replay_promotion_pending WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4)", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope], |row| row.get(0))?;
    if pending {
        return Err(ReplayStoreError::PromotionConflict);
    }
    let selected: Option<String> = tx.query_row("SELECT shadow_id FROM replay_active_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND selector='shadow'", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope], |row| row.get(0)).optional()?;
    if selected.as_deref().is_some_and(|id| id != shadow.0)
        || require_selected && selected.as_deref() != Some(shadow.as_str())
    {
        return Err(ReplayStoreError::ShadowConflict);
    }
    let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5 AND binding_digest=?6)", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0,scope.binding_digest], |row| row.get(0))?;
    exists.then_some(()).ok_or(ReplayStoreError::ShadowConflict)
}

fn exact_event(event: &ShadowEvent, transition: &ReplayTransition<'_>) -> bool {
    event.0 == transition.cursor
        && u64::try_from(event.1).ok() == Some(transition.generation)
        && u64::try_from(event.2).ok() == Some(transition.event_sequence)
        && event.3 == transition.event_bytes
        && event.4 == transition.event_digest
        && u64::try_from(event.5).ok() == Some(transition.projection_revision)
        && event.6 == transition.projection_digest
        && event.7 == transition.projection_bytes
}

fn shadow_checkpoint_for_transition(
    tx: &rusqlite::Transaction<'_>,
    scope: &ReplayScopeKey,
    shadow: &ShadowReplayId,
) -> Result<Option<ReplayCheckpoint>, ReplayStoreError> {
    let row: (i64, i64, i64, String, String, i64) = tx.query_row(
        "SELECT generation,event_sequence,projection_revision,cursor,projection_digest,baseline_sequence FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5",
        params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
    )?;
    if row.1 == 0 {
        return Ok(None);
    }
    Ok(Some(ReplayCheckpoint {
        cursor: row.3,
        generation: u64::try_from(row.0).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,
        event_sequence: u64::try_from(row.1).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,
        projection_revision: u64::try_from(row.2)
            .map_err(|_| ReplayStoreError::IntegerOutOfRange)?,
        projection_digest: row.4,
        binding_digest: scope.binding_digest.clone(),
    }))
}

fn validate_shadow_transition(
    current: Option<&ReplayCheckpoint>,
    transition: &ReplayTransition<'_>,
    tx: &rusqlite::Transaction<'_>,
    scope: &ReplayScopeKey,
    shadow: &ShadowReplayId,
) -> Result<(), ReplayStoreError> {
    let baseline: i64 = tx.query_row("SELECT baseline_sequence FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0], |row| row.get(0))?;
    match (current, transition.expected_checkpoint) {
        (None, None)
            if transition.event_sequence
                == u64::try_from(baseline)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ReplayStoreError::IntegerOutOfRange)?
                && transition.projection_revision == 1 =>
        {
            Ok(())
        }
        (Some(current), Some(expected))
            if current == expected
                && transition.cursor != current.cursor
                && transition.generation >= current.generation
                && current.event_sequence.checked_add(1) == Some(transition.event_sequence)
                && ((transition.projection_revision == current.projection_revision
                    && transition.projection_digest == current.projection_digest)
                    || current.projection_revision.checked_add(1)
                        == Some(transition.projection_revision)) =>
        {
            Ok(())
        }
        (None, _) | (Some(_), None) => Err(ReplayStoreError::CursorMismatch),
        _ => Err(ReplayStoreError::NonContiguousSequence),
    }
}
