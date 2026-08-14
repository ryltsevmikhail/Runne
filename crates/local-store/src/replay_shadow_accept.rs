use super::{
    LocalStore, OptionalExtension, ReplayScopeKey, ReplayStoreError, ShadowReplayId,
    ShadowResumeAcceptance, params, sha256_lower_hex, validate_replay_scope,
};
use gocode_secure_store::SecureStore;

type StoredAcceptance = (String, i64, i64, String, i64, String, Vec<u8>);

impl LocalStore {
    /// Replaces the shadow payload with the authenticated accepted-current view.
    ///
    /// Its cursor and sequence come only from the already verified baseline or
    /// suffix rows; callers cannot supply a cursor for this finalization.
    ///
    /// # Errors
    ///
    /// Returns an error when accepted state is not exactly the current shadow
    /// sequence or when the protected update cannot be sealed.
    pub fn finalize_authenticated_anchored_shadow_projection(
        &mut self,
        secure: &dyn SecureStore,
        scope: &ReplayScopeKey,
        shadow: &ShadowReplayId,
        accepted: &gocode_api::AuthenticatedAcceptedReplayProjectionV2,
        projection_revision: u64,
    ) -> Result<(), ReplayStoreError> {
        let payload = accepted
            .local_projection()
            .map_err(|_| ReplayStoreError::InvalidBaseline)?
            .local_persistence_bytes()
            .to_vec();
        self.commit_anchored_security_write(secure, |tx| {
            let current: Option<(i64, i64, String)> = tx.query_row(
                "SELECT event_sequence,baseline_sequence,witness_digest FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5 AND binding_digest=?6",
                params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0,scope.binding_digest],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional()?;
            let Some((current_sequence, baseline_sequence, witness_digest)) = current else {
                return Err(ReplayStoreError::ShadowConflict);
            };
            let evidence = decode_digest(&witness_digest).ok_or(ReplayStoreError::ShadowConflict)?;
            if u64::try_from(current_sequence).ok() != Some(accepted.sequence())
                || !accepted.matches_local_evidence_digest(&evidence)
            {
                return Err(ReplayStoreError::ShadowConflict);
            }
            let updated = tx.execute(
                "UPDATE replay_shadow_generations SET projection_payload=?6,projection_digest=?7,projection_revision=?8 WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5",
                params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0,payload,sha256_lower_hex(&payload),i64::try_from(projection_revision).map_err(|_| ReplayStoreError::IntegerOutOfRange)?],
            )?;
            if updated != 1 {
                return Err(ReplayStoreError::ShadowConflict);
            }
            if current_sequence > baseline_sequence {
                let event_updated = tx.execute(
                    "UPDATE replay_shadow_events SET projection_payload=?6,projection_digest=?7,projection_revision=?8 WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5 AND event_sequence=?9",
                    params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0,payload,sha256_lower_hex(&payload),i64::try_from(projection_revision).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,current_sequence],
                )?;
                if event_updated != 1 {
                    return Err(ReplayStoreError::ShadowConflict);
                }
            }
            Ok(((), true))
        })?;
        Ok(())
    }

    /// Seals a common authenticated baseline and its server-admitted cursor.
    ///
    /// The cursor is disclosed only inside the explicit native-Rust TCB
    /// callback; untrusted transport and UI code cannot assemble acceptance.
    ///
    /// # Errors
    ///
    /// Returns an error unless the capability-derived baseline exactly matches
    /// the immutable shadow evidence and the secure anchor write succeeds.
    pub fn accept_authenticated_anchored_shadow_baseline(
        &mut self,
        secure: &dyn SecureStore,
        scope: &ReplayScopeKey,
        shadow: &ShadowReplayId,
        baseline: &gocode_api::AuthenticatedReplayBaselineV2,
        checkpoint: &gocode_api::AuthenticatedReplayBaselineCheckpointV2,
        coordinates: super::ShadowPromotionCoordinates,
    ) -> Result<(), ReplayStoreError> {
        if !checkpoint.matches_baseline(baseline) {
            return Err(ReplayStoreError::InvalidBaseline);
        }
        let seed = super::ReplayBaselineSeed::from_authenticated_v2(scope, baseline)?;
        let payload = baseline
            .local_projection()
            .map_err(|_| ReplayStoreError::InvalidBaseline)?
            .local_persistence_bytes()
            .to_vec();
        let accepted = checkpoint.with_local_persistence_cursor(|cursor| ShadowResumeAcceptance {
            evidence_digest: super::baseline_evidence_digest(&seed),
            cursor: cursor.to_owned(),
            generation: coordinates.generation,
            event_sequence: baseline.sequence(),
            projection_revision: coordinates.projection_revision,
            projection_digest: sha256_lower_hex(&payload),
            projection_payload: payload,
        });
        self.accept_anchored_shadow_resume(secure, scope, shadow, &accepted)
    }

    /// Seals the server-accepted baseline cursor before a zero-suffix promotion.
    ///
    /// # Errors
    ///
    /// Returns an error when the opaque acceptance is malformed or conflicts
    /// with the persisted shadow evidence.
    pub fn accept_anchored_shadow_resume(
        &mut self,
        secure: &dyn SecureStore,
        scope: &ReplayScopeKey,
        shadow: &ShadowReplayId,
        accepted: &ShadowResumeAcceptance,
    ) -> Result<(), ReplayStoreError> {
        validate_replay_scope(scope)?;
        if accepted.cursor.is_empty()
            || accepted.projection_payload.is_empty()
            || sha256_lower_hex(&accepted.projection_payload) != accepted.projection_digest
        {
            return Err(ReplayStoreError::InvalidBaseline);
        }
        self.commit_anchored_security_write(secure, |tx| {
            let valid_json: i64 = tx.query_row(
                "SELECT json_valid(?1)",
                params![accepted.projection_payload],
                |row| row.get(0),
            )?;
            if valid_json != 1 {
                return Err(ReplayStoreError::CorruptProjectionJson);
            }
            let current: Option<StoredAcceptance> = tx.query_row(
                "SELECT baseline_digest,baseline_sequence,event_sequence,cursor,projection_revision,projection_digest,projection_payload FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5 AND binding_digest=?6",
                params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0,scope.binding_digest],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
            ).optional()?;
            let Some(current) = current else { return Err(ReplayStoreError::ShadowConflict); };
            let (digest, baseline, sequence, cursor, revision, projection_digest, projection) = current;
            if digest != accepted.evidence_digest
                || u64::try_from(baseline).ok() != Some(accepted.event_sequence)
            { return Err(ReplayStoreError::ShadowConflict); }
            let exact = sequence == baseline
                && cursor == accepted.cursor
                && u64::try_from(revision).ok() == Some(accepted.projection_revision)
                && projection_digest == accepted.projection_digest
                && projection == accepted.projection_payload;
            if exact { return Ok(((), false)); }
            if sequence != 0 || !cursor.is_empty() { return Err(ReplayStoreError::ShadowConflict); }
            tx.execute("UPDATE replay_shadow_generations SET projection_payload=?6,projection_digest=?7,projection_revision=?8,cursor=?9,generation=?10,event_sequence=?11 WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5", params![scope.runtime_authority,scope.principal,scope.lineage,scope.scope,shadow.0,accepted.projection_payload,accepted.projection_digest,i64::try_from(accepted.projection_revision).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,accepted.cursor,i64::try_from(accepted.generation).map_err(|_| ReplayStoreError::IntegerOutOfRange)?,i64::try_from(accepted.event_sequence).map_err(|_| ReplayStoreError::IntegerOutOfRange)?])?;
            Ok(((), true))
        })?;
        Ok(())
    }
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = [0; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(chunk[0])? << 4) | nibble(chunk[1])?;
    }
    Some(output)
}

const fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
