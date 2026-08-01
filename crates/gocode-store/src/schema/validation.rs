type ColumnShape = (&'static str, &'static str, bool, i64);

const VERIFICATION_EVIDENCE_COLUMNS: [ColumnShape; 12] = [
    ("evidence_id", "BLOB", false, 1),
    ("run_id", "BLOB", true, 0),
    ("profile_id", "BLOB", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("layer", "INTEGER", true, 0),
    ("evidence_type", "INTEGER", true, 0),
    ("evidence_digest", "BLOB", true, 0),
    ("content_ref", "TEXT", true, 0),
    ("source", "TEXT", true, 0),
    ("producer_identity", "TEXT", true, 0),
    ("sensitivity", "INTEGER", true, 0),
    ("verified_by", "TEXT", true, 0),
];
const CONSUMPTION_INTENT_COLUMNS: [ColumnShape; 6] = [
    ("intent_id", "BLOB", false, 1),
    ("idempotency_key", "TEXT", true, 0),
    ("state", "TEXT", true, 0),
    ("gate_head_snapshot_digest", "BLOB", true, 0),
    ("target_artifact_digest", "BLOB", true, 0),
    ("integrity_digest", "BLOB", true, 0),
];
const SCHEMA_LINEAGE_COLUMNS: [ColumnShape; 2] = [
    ("schema_version", "INTEGER", false, 1),
    ("provenance", "TEXT", true, 0),
];
const PROVIDER_PREPARED_COLUMNS: [ColumnShape; 5] = [
    ("call_id", "BLOB", false, 1),
    ("prepared_digest", "BLOB", true, 0),
    ("render_digest", "BLOB", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("record_digest", "BLOB", true, 0),
];
const PROVIDER_DISPATCH_COLUMNS: [ColumnShape; 13] = [
    ("attempt_id", "BLOB", false, 1),
    ("call_id", "BLOB", true, 0),
    ("permit_id", "BLOB", true, 0),
    ("token_reservation_id", "BLOB", true, 0),
    ("cost_reservation_id", "BLOB", true, 0),
    ("fencing_token", "INTEGER", true, 0),
    ("provider_idempotency_key", "TEXT", true, 0),
    ("prepared_digest", "BLOB", true, 0),
    ("render_digest", "BLOB", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("state", "INTEGER", true, 0),
    ("stream_id", "BLOB", false, 0),
    ("settlement_digest", "BLOB", false, 0),
];
const PROVIDER_EFFECT_AUTHORITY_COLUMNS: [ColumnShape; 17] = [
    ("authority_id", "BLOB", true, 1),
    ("revision", "INTEGER", true, 2),
    ("attempt_id", "BLOB", true, 0),
    ("permit_id", "BLOB", true, 0),
    ("capability_grant_id", "TEXT", true, 0),
    ("token_reservation_id", "BLOB", true, 0),
    ("cost_reservation_id", "BLOB", true, 0),
    ("prepared_digest", "BLOB", true, 0),
    ("render_digest", "BLOB", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("owner_id", "TEXT", true, 0),
    ("scope", "TEXT", true, 0),
    ("fencing_token", "INTEGER", true, 0),
    ("expires_at", "INTEGER", true, 0),
    ("revoked", "INTEGER", true, 0),
    ("consumed", "INTEGER", true, 0),
    ("consumed_intent_id", "TEXT", false, 0),
];

const CANONICAL_VERIFICATION_EVIDENCE_SQL: &str = "CREATE TABLE verification_evidence (evidence_id BLOB PRIMARY KEY CHECK(length(evidence_id) = 16), run_id BLOB NOT NULL CHECK(length(run_id) = 16), profile_id BLOB NOT NULL CHECK(length(profile_id) = 16), profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32), layer INTEGER NOT NULL CHECK(layer IN (0, 1, 2, 3, 4, 5)), evidence_type INTEGER NOT NULL CHECK(evidence_type IN (0, 1, 2, 3, 4)), evidence_digest BLOB NOT NULL CHECK(length(evidence_digest) = 32), content_ref TEXT NOT NULL CHECK(length(content_ref) > 0), source TEXT NOT NULL CHECK(length(source) > 0), producer_identity TEXT NOT NULL CHECK(length(producer_identity) > 0), sensitivity INTEGER NOT NULL CHECK(sensitivity IN (0, 1, 2)), verified_by TEXT NOT NULL CHECK(length(verified_by) > 0))";
const CANONICAL_CONSUMPTION_INTENTS_SQL: &str = "CREATE TABLE consumption_intents (intent_id BLOB PRIMARY KEY CHECK(length(intent_id) = 16), idempotency_key TEXT NOT NULL UNIQUE CHECK(length(idempotency_key) BETWEEN 1 AND 256), state TEXT NOT NULL CHECK(state IN ('Reserved','Dispatching','Completed','Failed','Invalidated','Abandoned')), gate_head_snapshot_digest BLOB NOT NULL CHECK(length(gate_head_snapshot_digest) = 32), target_artifact_digest BLOB NOT NULL CHECK(length(target_artifact_digest) = 32), integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32))";
const CANONICAL_SCHEMA_LINEAGE_SQL: &str = "CREATE TABLE schema_lineage (schema_version INTEGER PRIMARY KEY CHECK(schema_version = 9), provenance TEXT NOT NULL CHECK(provenance = 'released-v8-to-strict-v9'))";

fn table_shape_matches(
    conn: &Connection,
    table: &str,
    expected: &[ColumnShape],
) -> SqliteResult<bool> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info('{table}')"))?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? != 0,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?;
    Ok(actual.len() == expected.len()
        && actual.iter().zip(expected).all(
            |(
                (name, ty, not_null, pk),
                (expected_name, expected_ty, expected_not_null, expected_pk),
            )| {
                name == expected_name
                    && ty == expected_ty
                    && not_null == expected_not_null
                    && pk == expected_pk
            },
        ))
}

fn table_sql_matches(conn: &Connection, table: &str, expected: &str) -> SqliteResult<bool> {
    let actual: Option<String> = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )?;
    Ok(actual.is_some_and(|sql| normalize_sql(&sql) == normalize_sql(expected)))
}

fn table_sql_matches_migration(
    conn: &Connection,
    table: &str,
    migration: &str,
) -> SqliteResult<bool> {
    let ddl: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .optional()?;
    let Some(ddl) = ddl else {
        return Ok(false);
    };
    let expected = migration
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with(&format!("CREATE TABLE {table} ")));
    Ok(expected.is_some_and(|expected| normalize_ddl(&ddl) == normalize_ddl(expected)))
}

fn normalize_ddl(ddl: &str) -> String {
    let mut normalized = String::with_capacity(ddl.len());
    let mut characters = ddl.chars().peekable();
    let mut quoted = false;
    while let Some(character) = characters.next() {
        if quoted {
            normalized.extend(character.to_lowercase());
            if character == '\'' {
                quoted = false;
            }
            continue;
        }
        if character == '\'' {
            quoted = true;
            normalized.push(character);
        } else if character == '-' && characters.peek() == Some(&'-') {
            characters.next();
            while characters.next().is_some_and(|next| next != '\n') {}
        } else if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            while let Some(next) = characters.next() {
                if next == '*' && characters.peek() == Some(&'/') {
                    characters.next();
                    break;
                }
            }
        } else if !character.is_whitespace() {
            normalized.extend(character.to_lowercase());
        }
    }
    normalized
}

fn index_matches(
    conn: &Connection,
    index: &str,
    table: &str,
    columns: &[&str],
) -> SqliteResult<bool> {
    let actual_table: Option<String> = conn
        .query_row(
            "SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?1",
            [index],
            |row| row.get(0),
        )
        .optional()?;
    if actual_table.as_deref() != Some(table) {
        return Ok(false);
    }
    let mut list = conn.prepare(&format!("PRAGMA index_list('{table}')"))?;
    let exact_semantics = list
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? == 0,
                row.get::<_, String>(3)? == "c",
                row.get::<_, i64>(4)? == 0,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?
        .into_iter()
        .any(|(name, non_unique, created, not_partial)| {
            name == index && non_unique && created && not_partial
        });
    if !exact_semantics {
        return Ok(false);
    }
    let mut statement = conn.prepare(&format!("PRAGMA index_xinfo('{index}')"))?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?;
    let key_columns = actual
        .iter()
        .filter(|(_, _, _, _, _, key)| *key != 0)
        .collect::<Vec<_>>();
    Ok(key_columns.len() == columns.len()
        && key_columns.iter().zip(columns).all(
            |((sequence, column_id, name, descending, collation, _), expected)| {
                *sequence >= 0
                    && *column_id >= 0
                    && name.as_deref() == Some(*expected)
                    && *descending == 0
                    && collation == "BINARY"
            },
        ))
}

fn has_candidate_remnant(conn: &Connection) -> SqliteResult<bool> {
    let mut statement = conn.prepare(
        "SELECT type, name, tbl_name FROM sqlite_master WHERE type IN ('table', 'index', 'trigger', 'view')",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?;
    Ok(objects.iter().any(|(kind, name, table)| {
        let is_candidate_named = name.starts_with("verification_evidence_v")
            || name.starts_with("consumption_intents_v")
            || name.starts_with("schema_lineage_v")
            || name.starts_with("candidate_");
        let targets_owned_table = matches!(
            table.as_str(),
            "verification_evidence" | "consumption_intents" | "schema_lineage"
        );
        is_candidate_named
            || (targets_owned_table
                && !matches!(
                    (kind.as_str(), name.as_str()),
                    ("table", "verification_evidence")
                        | ("table", "consumption_intents")
                        | ("table", "schema_lineage")
                        | ("index", "idx_evidence_run")
                        | ("index", "sqlite_autoindex_consumption_intents_1")
                        | ("index", "sqlite_autoindex_consumption_intents_2")
                        | ("index", "sqlite_autoindex_verification_evidence_1")
                ))
    }))
}

fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace().collect()
}
