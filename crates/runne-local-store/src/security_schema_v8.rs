use crate::{Connection, SecurityStateError};

pub(crate) const SHADOW_TABLES_SQL: &str = "
CREATE TABLE replay_shadow_generations (
 runtime_authority TEXT NOT NULL, principal TEXT NOT NULL, lineage TEXT NOT NULL, scope TEXT NOT NULL,
 shadow_id TEXT NOT NULL CHECK(length(shadow_id) BETWEEN 8 AND 80), binding_digest TEXT NOT NULL CHECK(length(binding_digest)=64 AND binding_digest NOT GLOB '*[^0-9a-f]*'), scope_digest TEXT NOT NULL CHECK(length(scope_digest)=64 AND scope_digest NOT GLOB '*[^0-9a-f]*'), authenticated_scope_digest TEXT NOT NULL CHECK(length(authenticated_scope_digest)=64 AND authenticated_scope_digest NOT GLOB '*[^0-9a-f]*'), baseline_schema_version INTEGER NOT NULL CHECK(baseline_schema_version=2),
 session_binding TEXT NOT NULL CHECK(length(session_binding)=64 AND session_binding NOT GLOB '*[^0-9a-f]*'), promotion_codec TEXT NOT NULL CHECK(length(promotion_codec) BETWEEN 1 AND 64), head_event_id TEXT NOT NULL CHECK(length(head_event_id)=36 AND substr(head_event_id,15,1)='7' AND substr(head_event_id,20,1) IN ('8','9','a','b') AND head_event_id NOT GLOB '*[^0-9a-f-]*'), head_integrity_digest TEXT NOT NULL CHECK(length(head_integrity_digest)=64 AND head_integrity_digest NOT GLOB '*[^0-9a-f]*'), retention_manifest_digest TEXT NOT NULL CHECK(length(retention_manifest_digest)=64 AND retention_manifest_digest NOT GLOB '*[^0-9a-f]*'), witness_digest TEXT NOT NULL CHECK(length(witness_digest)=64 AND witness_digest NOT GLOB '*[^0-9a-f]*'),
 baseline_payload BLOB NOT NULL CHECK(length(baseline_payload) BETWEEN 1 AND 1048576), baseline_digest TEXT NOT NULL CHECK(length(baseline_digest)=64 AND baseline_digest NOT GLOB '*[^0-9a-f]*'),
 baseline_sequence INTEGER NOT NULL CHECK(baseline_sequence>=1), baseline_version INTEGER NOT NULL CHECK(baseline_version=baseline_sequence), baseline_position INTEGER NOT NULL CHECK(baseline_position>=1), retention_floor INTEGER NOT NULL CHECK(retention_floor>=1), retention_high_water INTEGER NOT NULL CHECK(retention_high_water>=retention_floor), retention_generation INTEGER NOT NULL CHECK(retention_generation>=1), issued_at INTEGER NOT NULL CHECK(issued_at>=1), expires_at INTEGER NOT NULL CHECK(expires_at>issued_at),
 projection_payload BLOB NOT NULL CHECK(length(projection_payload) BETWEEN 1 AND 1048576), projection_digest TEXT NOT NULL CHECK(length(projection_digest)=64 AND projection_digest NOT GLOB '*[^0-9a-f]*'),
 projection_revision INTEGER NOT NULL CHECK(projection_revision>=0), cursor TEXT NOT NULL CHECK(length(cursor)<=4096), generation INTEGER NOT NULL CHECK(generation>=0), event_sequence INTEGER NOT NULL CHECK(event_sequence>=0),
 PRIMARY KEY(runtime_authority,principal,lineage,scope,shadow_id)
) STRICT;
CREATE TABLE replay_shadow_events (
 runtime_authority TEXT NOT NULL, principal TEXT NOT NULL, lineage TEXT NOT NULL, scope TEXT NOT NULL, shadow_id TEXT NOT NULL,
 event_sequence INTEGER NOT NULL CHECK(event_sequence>=1), event_id TEXT NOT NULL CHECK(length(event_id) BETWEEN 1 AND 256), cursor TEXT NOT NULL CHECK(length(cursor) BETWEEN 1 AND 4096), generation INTEGER NOT NULL CHECK(generation>=0), event_payload BLOB NOT NULL CHECK(length(event_payload) BETWEEN 1 AND 1048576), event_digest TEXT NOT NULL CHECK(length(event_digest)=64 AND event_digest NOT GLOB '*[^0-9a-f]*'), projection_revision INTEGER NOT NULL CHECK(projection_revision>=0), projection_digest TEXT NOT NULL CHECK(length(projection_digest)=64 AND projection_digest NOT GLOB '*[^0-9a-f]*'), projection_payload BLOB NOT NULL CHECK(length(projection_payload) BETWEEN 1 AND 1048576 AND json_valid(projection_payload)=1),
 PRIMARY KEY(runtime_authority,principal,lineage,scope,shadow_id,event_sequence), UNIQUE(runtime_authority,principal,lineage,scope,shadow_id,event_id), UNIQUE(runtime_authority,principal,lineage,scope,shadow_id,cursor),
 FOREIGN KEY(runtime_authority,principal,lineage,scope,shadow_id) REFERENCES replay_shadow_generations(runtime_authority,principal,lineage,scope,shadow_id) ON DELETE RESTRICT
) STRICT;
CREATE TABLE replay_promotion_pending (
 runtime_authority TEXT NOT NULL, principal TEXT NOT NULL, lineage TEXT NOT NULL, scope TEXT NOT NULL,
 old_selector TEXT NOT NULL CHECK(old_selector IN ('legacy','shadow')), old_shadow_id TEXT, old_active_digest TEXT NOT NULL CHECK(length(old_active_digest)=64 AND old_active_digest NOT GLOB '*[^0-9a-f]*'),
 new_shadow_id TEXT NOT NULL, new_shadow_digest TEXT NOT NULL CHECK(length(new_shadow_digest)=64 AND new_shadow_digest NOT GLOB '*[^0-9a-f]*'),
 PRIMARY KEY(runtime_authority,principal,lineage,scope),
 CHECK((old_selector='legacy' AND old_shadow_id IS NULL) OR (old_selector='shadow' AND old_shadow_id IS NOT NULL)),
 FOREIGN KEY(runtime_authority,principal,lineage,scope,new_shadow_id) REFERENCES replay_shadow_generations(runtime_authority,principal,lineage,scope,shadow_id) ON DELETE RESTRICT
) STRICT;
CREATE TABLE replay_active_generations (
 runtime_authority TEXT NOT NULL, principal TEXT NOT NULL, lineage TEXT NOT NULL, scope TEXT NOT NULL,
 selector TEXT NOT NULL CHECK(selector IN ('legacy','shadow')), shadow_id TEXT,
 PRIMARY KEY(runtime_authority,principal,lineage,scope), CHECK((selector='legacy' AND shadow_id IS NULL) OR (selector='shadow' AND shadow_id IS NOT NULL))
) STRICT;";

pub(crate) fn validate_v8_schema(connection: &Connection) -> Result<(), SecurityStateError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let meta: (i64, i64, Option<String>, i64) = connection.query_row("SELECT schema_version,db_generation,last_transaction_digest,commit_marker FROM meta WHERE singleton=1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
    if version != 8
        || meta.0 != 8
        || meta.1 < 1
        || meta.2.as_deref().is_none_or(|value| !digest(value))
        || meta.3 != 1
        || !manifest(connection)?
        || !shadow_table_manifest(connection)?
        || !crate::security_schema_v7::v5_tables(connection)?
    {
        return Err(SecurityStateError::AdmissionFailed);
    }
    validate_shadow_rows(connection)
}

fn shadow_table_manifest(connection: &Connection) -> Result<bool, SecurityStateError> {
    for (table, indexes, foreign_keys) in [
        ("replay_shadow_generations", 1, 0),
        ("replay_shadow_events", 3, 5),
        ("replay_promotion_pending", 1, 5),
        ("replay_active_generations", 1, 0),
    ] {
        let actual: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )?;
        let Some(expected) = create_sql(table) else {
            return Ok(false);
        };
        let strict: i64 = connection.query_row(
            "SELECT strict FROM pragma_table_list WHERE name=?1",
            [table],
            |row| row.get(0),
        )?;
        let index_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM pragma_index_list(?1) WHERE origin IN ('pk','u')",
            [table],
            |row| row.get(0),
        )?;
        let foreign_key_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)",
            [table],
            |row| row.get(0),
        )?;
        if crate::recent_root_schema_normalize::normalize_sql(&actual)
            != crate::recent_root_schema_normalize::normalize_sql(expected)
            || strict != 1
            || index_count != indexes
            || foreign_key_count != foreign_keys
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn create_sql(table: &str) -> Option<&str> {
    let marker = format!("CREATE TABLE {table}");
    let start = SHADOW_TABLES_SQL.find(&marker)?;
    let end = start + SHADOW_TABLES_SQL[start..].find(';')?;
    Some(&SHADOW_TABLES_SQL[start..end])
}

fn manifest(connection: &Connection) -> Result<bool, SecurityStateError> {
    let mut actual = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort_unstable();
    let mut expected = crate::recent_root_schema_tables::TABLES
        .map(str::to_owned)
        .to_vec();
    expected.retain(|table| table != "mutation_ledger");
    expected.extend(
        [
            "mutation_ledger",
            "security_profile",
            "security_transactions",
            "replay_shadow_generations",
            "replay_shadow_events",
            "replay_promotion_pending",
            "replay_active_generations",
        ]
        .map(str::to_owned),
    );
    expected.sort_unstable();
    Ok(actual == expected
        && crate::security_schema_v7::has_only_canonical_schema_objects(connection)?)
}

fn validate_shadow_rows(connection: &Connection) -> Result<(), SecurityStateError> {
    let invalid: i64 = connection.query_row("SELECT (SELECT COUNT(*) FROM replay_shadow_events e LEFT JOIN replay_shadow_generations s USING(runtime_authority,principal,lineage,scope,shadow_id) WHERE s.shadow_id IS NULL)+(SELECT COUNT(*) FROM replay_promotion_pending p LEFT JOIN replay_shadow_generations n ON n.runtime_authority=p.runtime_authority AND n.principal=p.principal AND n.lineage=p.lineage AND n.scope=p.scope AND n.shadow_id=p.new_shadow_id LEFT JOIN replay_shadow_generations o ON o.runtime_authority=p.runtime_authority AND o.principal=p.principal AND o.lineage=p.lineage AND o.scope=p.scope AND o.shadow_id=p.old_shadow_id WHERE n.shadow_id IS NULL OR (p.old_selector='shadow' AND o.shadow_id IS NULL))+(SELECT COUNT(*) FROM replay_active_generations a LEFT JOIN replay_shadow_generations s ON s.runtime_authority=a.runtime_authority AND s.principal=a.principal AND s.lineage=a.lineage AND s.scope=a.scope AND s.shadow_id=a.shadow_id WHERE a.selector='shadow' AND s.shadow_id IS NULL)+(SELECT COUNT(*) FROM (SELECT runtime_authority,principal,lineage,scope FROM replay_cursors UNION SELECT runtime_authority,principal,lineage,scope FROM replay_shadow_generations UNION SELECT runtime_authority,principal,lineage,scope FROM replay_promotion_pending) q LEFT JOIN replay_active_generations a USING(runtime_authority,principal,lineage,scope) WHERE a.scope IS NULL)+(SELECT COUNT(*) FROM replay_shadow_generations s WHERE (s.event_sequence=0 AND (s.cursor!='' OR s.generation!=0 OR s.projection_revision!=0)) OR (s.event_sequence>0 AND (s.event_sequence!=s.baseline_sequence+(SELECT COUNT(*) FROM replay_shadow_events e WHERE e.runtime_authority=s.runtime_authority AND e.principal=s.principal AND e.lineage=s.lineage AND e.scope=s.scope AND e.shadow_id=s.shadow_id) OR s.cursor='' OR (s.event_sequence>s.baseline_sequence AND NOT EXISTS(SELECT 1 FROM replay_shadow_events e WHERE e.runtime_authority=s.runtime_authority AND e.principal=s.principal AND e.lineage=s.lineage AND e.scope=s.scope AND e.shadow_id=s.shadow_id AND e.event_sequence=s.event_sequence AND e.cursor=s.cursor AND e.generation=s.generation AND e.projection_revision=s.projection_revision AND e.projection_digest=s.projection_digest AND e.projection_payload=s.projection_payload)))))", [], |r| r.get(0))?;
    (invalid == 0)
        .then_some(())
        .ok_or(SecurityStateError::AdmissionFailed)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
