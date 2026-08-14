use super::{
    Anchored, LocalStore, OptionalExtension, ReplayBaselineSeed, ReplayCheckpoint, ReplayScopeKey,
    ReplayStoreError, ShadowReplayId, StoredConversationProjection, baseline_evidence_digest,
    params, read_replay_state, valid_baseline_seed, validate_replay_scope,
};
use gocode_secure_store::SecureStore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type PendingPromotion = (String, Option<String>, String, String, String);

impl LocalStore {
    pub(crate) fn recover_anchored_pending_promotions(
        &mut self,
        secure: &dyn SecureStore,
    ) -> Result<(), ReplayStoreError> {
        loop {
            let pending: Option<(ReplayScopeKey, ShadowReplayId)> = self.connection.query_row("SELECT p.runtime_authority,p.principal,p.lineage,p.scope,s.binding_digest,p.new_shadow_id FROM replay_promotion_pending p JOIN replay_shadow_generations s ON s.runtime_authority=p.runtime_authority AND s.principal=p.principal AND s.lineage=p.lineage AND s.scope=p.scope AND s.shadow_id=p.new_shadow_id ORDER BY p.runtime_authority,p.principal,p.lineage,p.scope LIMIT 1", [], |r| Ok((ReplayScopeKey { runtime_authority:r.get(0)?, principal:r.get(1)?, lineage:r.get(2)?, scope:r.get(3)?, binding_digest:r.get(4)? }, ShadowReplayId(r.get(5)?)))).optional()?;
            let Some((scope, shadow)) = pending else {
                return Ok(());
            };
            self.commit_anchored_shadow_promotion(secure, &scope, &shadow)?;
        }
    }

    /// # Errors
    ///
    /// Returns an error without writes unless the opaque baseline is valid and
    /// the connected security anchor can seal the isolated generation.
    pub fn begin_anchored_shadow_replay(
        &mut self,
        secure: &dyn SecureStore,
        scope: &ReplayScopeKey,
        seed: &ReplayBaselineSeed,
    ) -> Result<ShadowReplayId, ReplayStoreError> {
        validate_replay_scope(scope)?;
        let digest = baseline_evidence_digest(seed);
        let projection_digest = hex(&seed.payload);
        let id = ShadowReplayId(format!("shadow-{digest}"));
        let (result, _) = self.commit_anchored_security_write(secure, |tx| {
            if !valid_baseline_seed(scope, seed, unix_millis()?) {
                return Err(ReplayStoreError::InvalidBaseline);
            }
            let existing: Option<i64> = tx.query_row("SELECT 1 FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,id.0], |r| r.get(0)).optional()?;
            if existing.is_some() {
                let exact: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5 AND binding_digest=?6 AND scope_digest=?7 AND authenticated_scope_digest=?8 AND baseline_schema_version=?9 AND session_binding=?10 AND promotion_codec=?11 AND head_event_id=?12 AND head_integrity_digest=?13 AND retention_manifest_digest=?14 AND witness_digest=?15 AND baseline_payload=?16 AND baseline_digest=?17 AND baseline_sequence=?18 AND baseline_version=?19 AND baseline_position=?20 AND retention_floor=?21 AND retention_high_water=?22 AND retention_generation=?23 AND issued_at=?24 AND expires_at=?25)", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,id.0,scope.binding_digest,seed.scope_digest,seed.authenticated_scope_digest,i64::from(seed.schema_version),seed.session_binding,seed.promotion_codec,seed.head_event_id,seed.head_integrity_digest,seed.retention_manifest_digest,seed.witness_digest,seed.payload,digest,i64::try_from(seed.baseline_sequence).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.baseline_version).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.baseline_position).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.retention_floor).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.retention_high_water).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.retention_generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.issued_at).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.expires_at).map_err(|_| ReplayStoreError::IntegerOutOfRange)?], |r| r.get(0))?;
                return exact.then_some((id.clone(), false)).ok_or(ReplayStoreError::ShadowConflict);
            }
            tx.execute("INSERT INTO replay_active_generations(runtime_authority,principal,lineage,scope,selector,shadow_id) VALUES(?1,?2,?3,?4,'legacy',NULL) ON CONFLICT(runtime_authority,principal,lineage,scope) DO NOTHING", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope])?;
            tx.execute("INSERT INTO replay_shadow_generations(runtime_authority,principal,lineage,scope,shadow_id,binding_digest,scope_digest,authenticated_scope_digest,baseline_schema_version,session_binding,promotion_codec,head_event_id,head_integrity_digest,retention_manifest_digest,witness_digest,baseline_payload,baseline_digest,baseline_sequence,baseline_version,baseline_position,retention_floor,retention_high_water,retention_generation,issued_at,expires_at,projection_payload,projection_digest,projection_revision,cursor,generation,event_sequence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?16,?26,0,'',0,0)", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,id.0,scope.binding_digest,seed.scope_digest,seed.authenticated_scope_digest,i64::from(seed.schema_version),seed.session_binding,seed.promotion_codec,seed.head_event_id,seed.head_integrity_digest,seed.retention_manifest_digest,seed.witness_digest,seed.payload,digest,i64::try_from(seed.baseline_sequence).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.baseline_version).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.baseline_position).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.retention_floor).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.retention_high_water).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.retention_generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.issued_at).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(seed.expires_at).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,projection_digest])?;
            Ok((id.clone(), true))
        })?;
        Ok(result)
    }

    /// # Errors
    ///
    /// Returns an error if the expected active generation or shadow evidence
    /// differs from the sealed state.
    pub fn seal_anchored_shadow_promotion(
        &mut self,
        secure: &dyn SecureStore,
        scope: &ReplayScopeKey,
        shadow: &ShadowReplayId,
        expected_active: Option<&ReplayCheckpoint>,
    ) -> Result<(), ReplayStoreError> {
        validate_replay_scope(scope)?;
        self.commit_anchored_security_write(secure, |tx| {
            let selected = selector(tx, scope)?;
            let active = active_checkpoint(tx, scope, &selected)?;
            if active.as_ref() != expected_active { return Err(ReplayStoreError::PromotionConflict); }
            let shadow_digest = shadow_projection(tx, scope, shadow)?;
            let pending: Option<PendingPromotion> = tx.query_row("SELECT old_selector,old_shadow_id,old_active_digest,new_shadow_id,new_shadow_digest FROM replay_promotion_pending WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
            let old = crate::replay_shadow_digest::active_digest(tx, scope, &selected.0, selected.1.as_deref())?;
            if let Some(pending) = pending { return if pending == (selected.0, selected.1, old, shadow.0.clone(), shadow_digest) { Ok(((), false)) } else { Err(ReplayStoreError::PromotionConflict) }; }
            tx.execute("INSERT INTO replay_promotion_pending VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,selected.0,selected.1,old,shadow.0,shadow_digest])?;
            Ok(((), true))
        })?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error unless the exact pending promotion is sealed and the
    /// second anchored transaction read-back succeeds.
    pub fn commit_anchored_shadow_promotion(
        &mut self,
        secure: &dyn SecureStore,
        scope: &ReplayScopeKey,
        shadow: &ShadowReplayId,
    ) -> Result<Anchored<ReplayCheckpoint>, ReplayStoreError> {
        validate_replay_scope(scope)?;
        let (checkpoint, anchor) = self.commit_anchored_security_write(secure, |tx| {
            let pending: Option<PendingPromotion> = tx.query_row("SELECT old_selector,old_shadow_id,old_active_digest,new_shadow_id,new_shadow_digest FROM replay_promotion_pending WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
            if pending.is_none() {
                let selected = selector(tx, scope)?;
                if selected.0 == "shadow" && selected.1.as_deref() == Some(shadow.as_str()) {
                    return Ok((shadow_checkpoint(tx, scope, shadow)?, false));
                }
                return Err(ReplayStoreError::PromotionConflict);
            }
            let Some((old_selector, old_shadow, old_digest, pending_shadow, pending_digest)) = pending else { unreachable!() };
            if pending_shadow != shadow.0 { return Err(ReplayStoreError::PromotionConflict); }
            let current_old = crate::replay_shadow_digest::active_digest(tx, scope, &old_selector, old_shadow.as_deref())?;
            let current_new = crate::replay_shadow_digest::shadow_digest(tx, scope, shadow)?;
            if current_old != old_digest || current_new != pending_digest { return Err(ReplayStoreError::PromotionConflict); }
            let checkpoint = shadow_checkpoint(tx, scope, shadow)?;
            let pointer = tx.execute("UPDATE replay_active_generations SET selector='shadow',shadow_id=?5 WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND selector=?6 AND ((shadow_id IS NULL AND ?7 IS NULL) OR shadow_id=?7)", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0,old_selector,old_shadow])?;
            if pointer != 1 { return Err(ReplayStoreError::PromotionConflict); }
            let deleted = tx.execute("DELETE FROM replay_promotion_pending WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND old_selector=?5 AND ((old_shadow_id IS NULL AND ?6 IS NULL) OR old_shadow_id=?6) AND old_active_digest=?7 AND new_shadow_id=?8 AND new_shadow_digest=?9", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,old_selector,old_shadow,old_digest,shadow.0,pending_digest])?;
            if deleted != 1 { return Err(ReplayStoreError::PromotionConflict); }
            Ok((checkpoint, true))
        })?;
        Ok(Anchored {
            value: checkpoint,
            anchor,
        })
    }
}

fn selector(
    tx: &rusqlite::Transaction<'_>,
    scope: &ReplayScopeKey,
) -> Result<(String, Option<String>), ReplayStoreError> {
    Ok(tx.query_row("SELECT selector,shadow_id FROM replay_active_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope], |r| Ok((r.get(0)?,r.get(1)?))).optional()?.unwrap_or_else(|| ("legacy".into(),None)))
}
fn active_checkpoint(
    tx: &rusqlite::Transaction<'_>,
    scope: &ReplayScopeKey,
    selected: &(String, Option<String>),
) -> Result<Option<ReplayCheckpoint>, ReplayStoreError> {
    if selected.0 == "legacy" {
        Ok(read_replay_state(tx, scope)?.map(|state| state.checkpoint))
    } else {
        selected
            .1
            .as_ref()
            .map_or(Err(ReplayStoreError::PromotionConflict), |id| {
                shadow_checkpoint(tx, scope, &ShadowReplayId(id.clone())).map(Some)
            })
    }
}
fn shadow_projection(
    tx: &rusqlite::Transaction<'_>,
    scope: &ReplayScopeKey,
    shadow: &ShadowReplayId,
) -> Result<String, ReplayStoreError> {
    let _ = shadow_checkpoint(tx, scope, shadow)?;
    crate::replay_shadow_digest::shadow_digest(tx, scope, shadow)
}
fn shadow_checkpoint(
    tx: &rusqlite::Transaction<'_>,
    scope: &ReplayScopeKey,
    shadow: &ShadowReplayId,
) -> Result<ReplayCheckpoint, ReplayStoreError> {
    let (digest,revision,sequence,cursor,binding,generation,baseline):(String,i64,i64,String,String,i64,i64)=tx.query_row("SELECT projection_digest,projection_revision,event_sequence,cursor,binding_digest,generation,baseline_sequence FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5",params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).map_err(|_|ReplayStoreError::ShadowNotPromotable)?;
    if sequence == 0 || cursor.is_empty() {
        return Err(ReplayStoreError::ShadowNotPromotable);
    }
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM replay_shadow_events WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0], |row| row.get(0))?;
    if baseline.checked_add(count) != Some(sequence) {
        return Err(ReplayStoreError::ShadowNotPromotable);
    }
    Ok(ReplayCheckpoint {
        cursor,
        generation: u64::try_from(generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,
        event_sequence: u64::try_from(sequence).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,
        projection_revision: u64::try_from(revision)
            .map_err(|_| ReplayStoreError::IntegerOutOfRange)?,
        projection_digest: digest,
        binding_digest: binding,
    })
}
fn hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn unix_millis() -> Result<u64, ReplayStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReplayStoreError::InvalidBaseline)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}

pub(crate) fn selected_shadow(
    connection: &rusqlite::Connection,
    scope: &ReplayScopeKey,
) -> Result<Option<ShadowReplayId>, ReplayStoreError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version < 8 {
        return Ok(None);
    }
    let selected: Option<(String, Option<String>)> = connection.query_row("SELECT selector,shadow_id FROM replay_active_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    match selected {
        None if scope_has_state(connection, scope)? => Err(ReplayStoreError::PromotionConflict),
        None => Ok(None),
        Some((selector, None)) if selector == "legacy" => Ok(None),
        Some((selector, Some(id))) if selector == "shadow" => Ok(Some(ShadowReplayId(id))),
        _ => Err(ReplayStoreError::PromotionConflict),
    }
}

fn scope_has_state(
    connection: &rusqlite::Connection,
    scope: &ReplayScopeKey,
) -> Result<bool, ReplayStoreError> {
    connection.query_row("SELECT EXISTS(SELECT 1 FROM event_journal WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 UNION SELECT 1 FROM projections WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 UNION SELECT 1 FROM replay_cursors WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 UNION SELECT 1 FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 UNION SELECT 1 FROM replay_promotion_pending WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4)", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope], |row| row.get(0)).map_err(Into::into)
}

pub(crate) fn shadow_projection_for_scope(
    connection: &rusqlite::Connection,
    scope: &ReplayScopeKey,
    shadow: &ShadowReplayId,
) -> Result<StoredConversationProjection, ReplayStoreError> {
    let (payload, digest, revision, sequence, binding):(Vec<u8>,String,i64,i64,String)=connection.query_row("SELECT projection_payload,projection_digest,projection_revision,event_sequence,binding_digest FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5",params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(|_|ReplayStoreError::ShadowNotPromotable)?;
    if binding != scope.binding_digest || hex(&payload) != digest {
        return Err(ReplayStoreError::ProjectionDigestMismatch);
    }
    Ok(StoredConversationProjection {
        payload,
        revision: u64::try_from(revision).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,
        digest,
        event_sequence: u64::try_from(sequence).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,
        binding_digest: binding,
    })
}

pub(crate) fn shadow_checkpoint_for_scope(
    connection: &rusqlite::Connection,
    scope: &ReplayScopeKey,
    shadow: &ShadowReplayId,
) -> Result<ReplayCheckpoint, ReplayStoreError> {
    let (digest, revision, sequence, cursor, binding, generation): (String, i64, i64, String, String, i64) = connection.query_row(
        "SELECT projection_digest,projection_revision,event_sequence,cursor,binding_digest,generation FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5",
        params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
    ).map_err(|_| ReplayStoreError::ShadowNotPromotable)?;
    if sequence == 0 || cursor.is_empty() || binding != scope.binding_digest {
        return Err(ReplayStoreError::ShadowNotPromotable);
    }
    Ok(ReplayCheckpoint {
        cursor,
        generation: u64::try_from(generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,
        event_sequence: u64::try_from(sequence).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,
        projection_revision: u64::try_from(revision)
            .map_err(|_| ReplayStoreError::IntegerOutOfRange)?,
        projection_digest: digest,
        binding_digest: binding,
    })
}
