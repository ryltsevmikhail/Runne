use rusqlite::params;

const TABLE: &str = "provider_subscription_budgets";

pub(super) fn apply_v38_migration(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS provider_subscription_budgets (
            provider_id TEXT NOT NULL,
            credential_version INTEGER NOT NULL CHECK(credential_version > 0),
            remaining_tokens INTEGER NOT NULL CHECK(remaining_tokens >= 0),
            updated_at_high_water INTEGER,
            PRIMARY KEY(provider_id, credential_version)
        );
        INSERT INTO schema_version (version) VALUES (38);",
    )
}

pub(super) fn v38_matches(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 38 {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = conn.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if !matches!(marker, (38, 1, 37, 722) | (38, 1, 38, 741)) {
        return Ok(false);
    }
    let sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [TABLE],
            |row| row.get(0),
        )
        .optional()?;
    let expected = "CREATE TABLE provider_subscription_budgets ( provider_id TEXT NOT NULL, credential_version INTEGER NOT NULL CHECK(credential_version > 0), remaining_tokens INTEGER NOT NULL CHECK(remaining_tokens >= 0), updated_at_high_water INTEGER, PRIMARY KEY(provider_id, credential_version) )";
    let own_structure_matches = sql
        .as_ref()
        .is_some_and(|sql| normalize_ddl(sql) == normalize_ddl(expected));
    let inherited = catalog_marker_matches(conn)?
        && inherited_credential_guards_match(conn)?
        && v37_structure_matches(conn)?
        && v38_catalog_matches(conn)?;
    Ok(inherited && own_structure_matches)
}

fn v38_catalog_matches(conn: &Connection) -> SqliteResult<bool> {
    v29_catalog_matches_with_extensions(
        conn,
        v35_operation_index_names(),
        &CredentialSchemaExtensions {
            tables: &[V33_TABLE, V35_TABLE, TABLE],
            indexes: &[V33_INDEX],
            triggers: &[],
            replacements: &[],
        },
    )
}

/// Seed a positive local budget exactly once for a credential version.
pub fn seed_subscription_budget(
    conn: &Connection,
    provider_id: &str,
    credential_version: u64,
    budget: u64,
) -> SqliteResult<bool> {
    let changed = conn.execute(
        "INSERT OR IGNORE INTO provider_subscription_budgets
         (provider_id, credential_version, remaining_tokens)
         VALUES (?1, ?2, ?3)",
        params![
            provider_id,
            i64::try_from(credential_version).unwrap_or(i64::MAX),
            i64::try_from(budget).unwrap_or(i64::MAX)
        ],
    )?;
    Ok(changed == 1)
}

/// Reads the durable budget; a missing row is intentionally distinguishable.
pub fn subscription_budget(
    conn: &Connection,
    provider_id: &str,
    credential_version: u64,
) -> SqliteResult<Option<u64>> {
    conn.query_row(
        "SELECT remaining_tokens FROM provider_subscription_budgets
         WHERE provider_id=?1 AND credential_version=?2",
        params![
            provider_id,
            i64::try_from(credential_version).unwrap_or(i64::MAX)
        ],
        |row| row.get::<_, i64>(0).map(|value| value as u64),
    )
    .optional()
}

/// Decrements a budget atomically and floors at zero.
pub fn spend_subscription_budget(
    conn: &Connection,
    provider_id: &str,
    credential_version: u64,
    tokens: u64,
) -> SqliteResult<bool> {
    let changed = conn.execute(
        "UPDATE provider_subscription_budgets
         SET remaining_tokens = MAX(0, remaining_tokens - ?3)
         WHERE provider_id=?1 AND credential_version=?2 AND remaining_tokens >= 0",
        params![
            provider_id,
            i64::try_from(credential_version).unwrap_or(i64::MAX),
            i64::try_from(tokens).unwrap_or(i64::MAX)
        ],
    )?;
    Ok(changed == 1)
}

/// Replaces a budget only with an observed non-negative provider value.
pub fn refresh_subscription_budget(
    conn: &Connection,
    provider_id: &str,
    credential_version: u64,
    remaining_tokens: u64,
    updated_at_high_water: i64,
) -> SqliteResult<bool> {
    let changed = conn.execute(
        "UPDATE provider_subscription_budgets SET remaining_tokens=?3,
         updated_at_high_water=?4 WHERE provider_id=?1 AND credential_version=?2
         AND (updated_at_high_water IS NULL OR updated_at_high_water < ?4)",
        params![
            provider_id,
            i64::try_from(credential_version).unwrap_or(i64::MAX),
            i64::try_from(remaining_tokens).unwrap_or(i64::MAX),
            updated_at_high_water
        ],
    )?;
    Ok(changed == 1)
}
