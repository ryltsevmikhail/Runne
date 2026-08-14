use crate::{Connection, Digest, SecurityStateError, Sha256};

pub(crate) fn protected_state_root(
    connection: &Connection,
) -> Result<[u8; 32], SecurityStateError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let mut hasher = Sha256::new();
    hasher.update(if version >= 8 {
        b"gocode/local-store/protected-state-root/v2\0"
    } else {
        b"gocode/local-store/protected-state-root/v1\0"
    });
    if version == 6 {
        ledger_rows_v6(connection, &mut hasher)?;
    } else {
        ledger_rows(connection, &mut hasher)?;
    }
    replay_rows(connection, &mut hasher)?;
    if version >= 8 {
        shadow_rows(connection, &mut hasher)?;
    }
    Ok(hasher.finalize().into())
}

fn ledger_rows_v6(connection: &Connection, hasher: &mut Sha256) -> Result<(), SecurityStateError> {
    let mut statement = connection.prepare("SELECT runtime_authority_digest,principal_digest,operation_kind,target_kind,target_id,idempotency_key,expected_version,semantic_digest,client_disposition,runtime_disposition,command_ref,outcome_ref,recovery_summary,created_at,updated_at FROM mutation_ledger ORDER BY runtime_authority_digest,principal_digest,idempotency_key")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Vec<u8>>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Option<String>>(9)?,
            row.get::<_, Option<Vec<u8>>>(10)?,
            row.get::<_, Option<Vec<u8>>>(11)?,
            row.get::<_, String>(12)?,
            row.get::<_, i64>(13)?,
            row.get::<_, i64>(14)?,
        ))
    })?;
    hasher.update(b"mutation_ledger\0");
    for row in rows {
        let row = row?;
        bytes(hasher, &row.0);
        bytes(hasher, &row.1);
        text(hasher, &row.2);
        text(hasher, &row.3);
        bytes(hasher, &row.4);
        text(hasher, &row.5);
        integer(hasher, row.6);
        bytes(hasher, &row.7);
        text(hasher, &row.8);
        optional_text(hasher, row.9.as_deref());
        optional_bytes(hasher, row.10.as_deref());
        optional_bytes(hasher, row.11.as_deref());
        text(hasher, &row.12);
        integer(hasher, row.13);
        integer(hasher, row.14);
    }
    Ok(())
}

pub(crate) fn empty_protected_state_root() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/local-store/protected-state-root/v2\0");
    hasher.update(b"mutation_ledger\0event_journal\0projections\0replay_cursors\0replay_shadow_generations\0replay_shadow_events\0replay_promotion_pending\0replay_active_generations\0");
    hasher.finalize().into()
}

fn shadow_rows(connection: &Connection, hasher: &mut Sha256) -> Result<(), SecurityStateError> {
    rows(
        connection,
        hasher,
        "replay_shadow_generations",
        "SELECT runtime_authority,principal,lineage,scope,shadow_id,binding_digest,scope_digest,authenticated_scope_digest,baseline_schema_version,session_binding,promotion_codec,head_event_id,head_integrity_digest,retention_manifest_digest,witness_digest,baseline_payload,baseline_digest,baseline_sequence,baseline_version,baseline_position,retention_floor,retention_high_water,retention_generation,issued_at,expires_at,projection_payload,projection_digest,projection_revision,cursor,generation,event_sequence FROM replay_shadow_generations ORDER BY runtime_authority,principal,lineage,scope,shadow_id",
    )?;
    rows(
        connection,
        hasher,
        "replay_shadow_events",
        "SELECT runtime_authority,principal,lineage,scope,shadow_id,event_sequence,event_id,cursor,generation,event_payload,event_digest,projection_revision,projection_digest,projection_payload FROM replay_shadow_events ORDER BY runtime_authority,principal,lineage,scope,shadow_id,event_sequence",
    )?;
    rows(
        connection,
        hasher,
        "replay_promotion_pending",
        "SELECT runtime_authority,principal,lineage,scope,old_selector,old_shadow_id,old_active_digest,new_shadow_id,new_shadow_digest FROM replay_promotion_pending ORDER BY runtime_authority,principal,lineage,scope",
    )?;
    rows(
        connection,
        hasher,
        "replay_active_generations",
        "SELECT runtime_authority,principal,lineage,scope,selector,shadow_id FROM replay_active_generations ORDER BY runtime_authority,principal,lineage,scope",
    )
}

fn rows(
    connection: &Connection,
    hasher: &mut Sha256,
    name: &str,
    query: &str,
) -> Result<(), SecurityStateError> {
    hasher.update(name.as_bytes());
    hasher.update([0]);
    let mut statement = connection.prepare(query)?;
    let count = statement.column_count();
    let mut result = statement.query([])?;
    while let Some(row) = result.next()? {
        for index in 0..count {
            match row.get_ref(index)? {
                rusqlite::types::ValueRef::Null => hasher.update([0]),
                rusqlite::types::ValueRef::Integer(value) => integer(hasher, value),
                rusqlite::types::ValueRef::Text(value) => text(
                    hasher,
                    std::str::from_utf8(value).map_err(|_| SecurityStateError::AdmissionFailed)?,
                ),
                rusqlite::types::ValueRef::Blob(value) => bytes(hasher, value),
                rusqlite::types::ValueRef::Real(_) => {
                    return Err(SecurityStateError::AdmissionFailed);
                }
            }
        }
    }
    Ok(())
}

fn ledger_rows(connection: &Connection, hasher: &mut Sha256) -> Result<(), SecurityStateError> {
    let mut statement = connection.prepare("SELECT runtime_authority_digest,principal_digest,operation_kind,target_kind,target_id,idempotency_key,expected_version,semantic_digest,normalized_command,canonical_outcome,resend_count,client_disposition,runtime_disposition,command_ref,outcome_ref,recovery_summary,created_at,updated_at FROM mutation_ledger ORDER BY runtime_authority_digest,principal_digest,idempotency_key")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Vec<u8>>(7)?,
            row.get::<_, Option<Vec<u8>>>(8)?,
            row.get::<_, Option<Vec<u8>>>(9)?,
            row.get::<_, i64>(10)?,
            row.get::<_, String>(11)?,
            row.get::<_, Option<String>>(12)?,
            row.get::<_, Option<Vec<u8>>>(13)?,
            row.get::<_, Option<Vec<u8>>>(14)?,
            row.get::<_, String>(15)?,
            row.get::<_, i64>(16)?,
            row.get::<_, i64>(17)?,
        ))
    })?;
    hasher.update(b"mutation_ledger\0");
    for row in rows {
        let row = row?;
        bytes(hasher, &row.0);
        bytes(hasher, &row.1);
        text(hasher, &row.2);
        text(hasher, &row.3);
        bytes(hasher, &row.4);
        text(hasher, &row.5);
        integer(hasher, row.6);
        bytes(hasher, &row.7);
        optional_bytes(hasher, row.8.as_deref());
        optional_bytes(hasher, row.9.as_deref());
        integer(hasher, row.10);
        text(hasher, &row.11);
        optional_text(hasher, row.12.as_deref());
        optional_bytes(hasher, row.13.as_deref());
        optional_bytes(hasher, row.14.as_deref());
        text(hasher, &row.15);
        integer(hasher, row.16);
        integer(hasher, row.17);
    }
    Ok(())
}

fn replay_rows(connection: &Connection, hasher: &mut Sha256) -> Result<(), SecurityStateError> {
    let mut journal = connection.prepare("SELECT runtime_authority,principal,lineage,scope,binding_digest,event_id,cursor,generation,event_sequence,validated_event,event_digest,projection_revision,projection_digest,projected_payload FROM event_journal ORDER BY runtime_authority,principal,lineage,scope,event_id")?;
    hasher.update(b"event_journal\0");
    for row in journal.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, i64>(7)?,
            r.get::<_, i64>(8)?,
            r.get::<_, Vec<u8>>(9)?,
            r.get::<_, String>(10)?,
            r.get::<_, i64>(11)?,
            r.get::<_, String>(12)?,
            r.get::<_, Vec<u8>>(13)?,
        ))
    })? {
        let r = row?;
        text(hasher, &r.0);
        text(hasher, &r.1);
        text(hasher, &r.2);
        text(hasher, &r.3);
        text(hasher, &r.4);
        text(hasher, &r.5);
        text(hasher, &r.6);
        integer(hasher, r.7);
        integer(hasher, r.8);
        bytes(hasher, &r.9);
        text(hasher, &r.10);
        integer(hasher, r.11);
        text(hasher, &r.12);
        bytes(hasher, &r.13);
    }
    let mut projections = connection.prepare("SELECT runtime_authority,principal,lineage,scope,binding_digest,projection_revision,projection_digest,event_sequence,payload FROM projections ORDER BY runtime_authority,principal,lineage,scope")?;
    hasher.update(b"projections\0");
    for row in projections.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, i64>(7)?,
            r.get::<_, Vec<u8>>(8)?,
        ))
    })? {
        let r = row?;
        text(hasher, &r.0);
        text(hasher, &r.1);
        text(hasher, &r.2);
        text(hasher, &r.3);
        text(hasher, &r.4);
        integer(hasher, r.5);
        text(hasher, &r.6);
        integer(hasher, r.7);
        bytes(hasher, &r.8);
    }
    let mut cursors = connection.prepare("SELECT runtime_authority,principal,lineage,scope,binding_digest,generation,applied_cursor,event_sequence,projection_revision,projection_digest FROM replay_cursors ORDER BY runtime_authority,principal,lineage,scope")?;
    hasher.update(b"replay_cursors\0");
    for row in cursors.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, i64>(7)?,
            r.get::<_, i64>(8)?,
            r.get::<_, String>(9)?,
        ))
    })? {
        let r = row?;
        text(hasher, &r.0);
        text(hasher, &r.1);
        text(hasher, &r.2);
        text(hasher, &r.3);
        text(hasher, &r.4);
        integer(hasher, r.5);
        text(hasher, &r.6);
        integer(hasher, r.7);
        integer(hasher, r.8);
        text(hasher, &r.9);
    }
    Ok(())
}

fn bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update([1]);
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}
fn text(hasher: &mut Sha256, value: &str) {
    bytes(hasher, value.as_bytes());
}
fn optional_bytes(hasher: &mut Sha256, value: Option<&[u8]>) {
    match value {
        Some(value) => bytes(hasher, value),
        None => hasher.update([0]),
    }
}
fn optional_text(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => text(hasher, value),
        None => hasher.update([0]),
    }
}
fn integer(hasher: &mut Sha256, value: i64) {
    hasher.update([2]);
    hasher.update(value.to_be_bytes());
}
