use super::{ReplayScopeKey, ReplayStoreError, Sha256, ShadowReplayId, params};
use sha2::Digest;

pub fn active_digest(
    tx: &rusqlite::Transaction<'_>,
    scope: &ReplayScopeKey,
    selector: &str,
    shadow: Option<&str>,
) -> Result<String, ReplayStoreError> {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/local-store/replay-active-v8\0");
    text(&mut hasher, selector);
    optional_text(&mut hasher, shadow);
    if selector == "legacy" {
        for query in [
            "SELECT binding_digest,event_id,cursor,generation,event_sequence,validated_event,event_digest,projection_revision,projection_digest,projected_payload FROM event_journal WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 ORDER BY event_sequence",
            "SELECT binding_digest,projection_revision,projection_digest,event_sequence,payload FROM projections WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4",
            "SELECT binding_digest,generation,applied_cursor,event_sequence,projection_revision,projection_digest FROM replay_cursors WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4",
        ] {
            hash_rows(tx, query, scope, &mut hasher)?;
        }
    } else {
        let id = shadow.ok_or(ReplayStoreError::PromotionConflict)?;
        hash_shadow_generation(tx, scope, id, &mut hasher)?;
        hash_shadow_events(tx, scope, id, &mut hasher)?;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn shadow_digest(
    tx: &rusqlite::Transaction<'_>,
    scope: &ReplayScopeKey,
    shadow: &ShadowReplayId,
) -> Result<String, ReplayStoreError> {
    active_digest(tx, scope, "shadow", Some(shadow.as_str()))
}

fn hash_rows(
    tx: &rusqlite::Transaction<'_>,
    query: &str,
    scope: &ReplayScopeKey,
    hasher: &mut Sha256,
) -> Result<(), ReplayStoreError> {
    hasher.update(query.as_bytes());
    let mut statement = tx.prepare(query)?;
    let columns = statement.column_count();
    let mut rows = statement.query(params![
        scope.runtime_authority,
        scope.principal,
        scope.lineage,
        scope.scope
    ])?;
    while let Some(row) = rows.next()? {
        hash_row(row, columns, hasher)?;
    }
    Ok(())
}

fn hash_shadow_events(
    tx: &rusqlite::Transaction<'_>,
    scope: &ReplayScopeKey,
    shadow: &str,
    hasher: &mut Sha256,
) -> Result<(), ReplayStoreError> {
    let mut statement = tx.prepare("SELECT event_sequence,event_id,cursor,generation,event_payload,event_digest,projection_revision,projection_digest,projection_payload FROM replay_shadow_events WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5 ORDER BY event_sequence")?;
    let columns = statement.column_count();
    let mut rows = statement.query(params![
        scope.runtime_authority,
        scope.principal,
        scope.lineage,
        scope.scope,
        shadow
    ])?;
    while let Some(row) = rows.next()? {
        hash_row(row, columns, hasher)?;
    }
    Ok(())
}

fn hash_shadow_generation(
    tx: &rusqlite::Transaction<'_>,
    scope: &ReplayScopeKey,
    shadow: &str,
    hasher: &mut Sha256,
) -> Result<(), ReplayStoreError> {
    let query = "SELECT binding_digest,scope_digest,authenticated_scope_digest,baseline_schema_version,session_binding,promotion_codec,head_event_id,head_integrity_digest,retention_manifest_digest,witness_digest,baseline_payload,baseline_digest,baseline_sequence,baseline_version,baseline_position,retention_floor,retention_high_water,retention_generation,issued_at,expires_at,projection_payload,projection_digest,projection_revision,cursor,generation,event_sequence FROM replay_shadow_generations WHERE runtime_authority=?1 AND principal=?2 AND lineage=?3 AND scope=?4 AND shadow_id=?5";
    hasher.update(query.as_bytes());
    let mut statement = tx.prepare(query)?;
    let columns = statement.column_count();
    let mut rows = statement.query(params![
        scope.runtime_authority,
        scope.principal,
        scope.lineage,
        scope.scope,
        shadow
    ])?;
    let Some(row) = rows.next()? else {
        return Err(ReplayStoreError::ShadowNotPromotable);
    };
    hash_row(row, columns, hasher)
}

fn hash_row(
    row: &rusqlite::Row<'_>,
    columns: usize,
    hasher: &mut Sha256,
) -> Result<(), ReplayStoreError> {
    for index in 0..columns {
        match row.get_ref(index)? {
            rusqlite::types::ValueRef::Null => hasher.update([0]),
            rusqlite::types::ValueRef::Integer(value) => {
                hasher.update([1]);
                hasher.update(value.to_be_bytes());
            }
            rusqlite::types::ValueRef::Text(value) | rusqlite::types::ValueRef::Blob(value) => {
                bytes(hasher, value);
            }
            rusqlite::types::ValueRef::Real(_) => return Err(ReplayStoreError::PromotionConflict),
        }
    }
    Ok(())
}

fn bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update([2]);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}
fn text(hasher: &mut Sha256, value: &str) {
    bytes(hasher, value.as_bytes());
}
fn optional_text(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => text(hasher, value),
        None => hasher.update([0]),
    }
}
