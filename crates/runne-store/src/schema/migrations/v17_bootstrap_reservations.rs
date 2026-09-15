const MIGRATION_V17: &str = r#"
CREATE TABLE bootstrap_reservations (
    reservation_key BLOB PRIMARY KEY CHECK(length(reservation_key) = 32),
    challenge_id BLOB NOT NULL UNIQUE CHECK(length(challenge_id) = 16),
    server_nonce BLOB NOT NULL CHECK(length(server_nonce) = 32),
    binding_proof BLOB NOT NULL CHECK(length(binding_proof) = 32),
    key_version INTEGER NOT NULL CHECK(key_version = 1),
    client_nonce BLOB NOT NULL CHECK(length(client_nonce) = 32),
    not_before_rfc3339_utc_microseconds TEXT NOT NULL CHECK(length(not_before_rfc3339_utc_microseconds) = 27),
    expiry_rfc3339_utc_microseconds TEXT NOT NULL CHECK(length(expiry_rfc3339_utc_microseconds) = 27),
    not_before_unix_microseconds INTEGER NOT NULL CHECK(not_before_unix_microseconds >= 0),
    expiry_unix_microseconds INTEGER NOT NULL CHECK(expiry_unix_microseconds > not_before_unix_microseconds),
    reserved_at_unix_microseconds INTEGER NOT NULL CHECK(reserved_at_unix_microseconds >= not_before_unix_microseconds AND reserved_at_unix_microseconds < expiry_unix_microseconds),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 8),
    fence INTEGER NOT NULL CHECK(fence > 0),
    reservation_state TEXT NOT NULL CHECK(reservation_state IN ('RESERVED', 'CONSUMED', 'FENCED')),
    authority_digest BLOB CHECK(authority_digest IS NULL OR length(authority_digest) = 32),
    consumed_at_unix_microseconds INTEGER,
    CHECK(
        (reservation_state = 'RESERVED' AND attempt_count < 8 AND authority_digest IS NULL AND consumed_at_unix_microseconds IS NULL)
        OR (reservation_state = 'FENCED' AND attempt_count = 8 AND authority_digest IS NULL AND consumed_at_unix_microseconds IS NULL)
        OR (reservation_state = 'CONSUMED' AND authority_digest IS NOT NULL AND consumed_at_unix_microseconds IS NOT NULL AND consumed_at_unix_microseconds < expiry_unix_microseconds)
    )
);
CREATE INDEX bootstrap_reservation_unexpired
    ON bootstrap_reservations(expiry_unix_microseconds, reservation_state);
CREATE TABLE bootstrap_reservation_tombstones (
    reservation_key BLOB PRIMARY KEY REFERENCES bootstrap_reservations(reservation_key),
    challenge_id BLOB NOT NULL UNIQUE CHECK(length(challenge_id) = 16),
    binding_proof BLOB NOT NULL CHECK(length(binding_proof) = 32),
    authority_digest BLOB NOT NULL CHECK(length(authority_digest) = 32),
    consumed_at_unix_microseconds INTEGER NOT NULL CHECK(consumed_at_unix_microseconds >= 0),
    expiry_unix_microseconds INTEGER NOT NULL CHECK(expiry_unix_microseconds > consumed_at_unix_microseconds),
    fence INTEGER NOT NULL CHECK(fence > 0)
);
CREATE TABLE bootstrap_last_observed_clock (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    observed_at INTEGER NOT NULL CHECK(observed_at >= 0)
);
INSERT INTO bootstrap_last_observed_clock (id, observed_at) VALUES (1, 0);
"#;

const V17_TRIGGERS: [(&str, &str); 7] = [
    (
        "bootstrap_reservation_transition_order",
        "CREATE TRIGGER bootstrap_reservation_transition_order BEFORE UPDATE ON bootstrap_reservations WHEN NEW.reservation_key != OLD.reservation_key OR NEW.challenge_id != OLD.challenge_id OR NEW.server_nonce != OLD.server_nonce OR NEW.binding_proof != OLD.binding_proof OR NEW.key_version != OLD.key_version OR NEW.client_nonce != OLD.client_nonce OR NEW.not_before_rfc3339_utc_microseconds != OLD.not_before_rfc3339_utc_microseconds OR NEW.expiry_rfc3339_utc_microseconds != OLD.expiry_rfc3339_utc_microseconds OR NEW.not_before_unix_microseconds != OLD.not_before_unix_microseconds OR NEW.expiry_unix_microseconds != OLD.expiry_unix_microseconds OR NEW.reserved_at_unix_microseconds != OLD.reserved_at_unix_microseconds OR NEW.fence != OLD.fence OR NEW.attempt_count < OLD.attempt_count OR NEW.attempt_count > OLD.attempt_count + 1 OR OLD.reservation_state IN ('CONSUMED', 'FENCED') OR NOT (NEW.reservation_state = OLD.reservation_state OR (OLD.reservation_state = 'RESERVED' AND NEW.reservation_state IN ('CONSUMED', 'FENCED'))) BEGIN SELECT RAISE(ABORT, 'invalid bootstrap reservation transition'); END",
    ),
    (
        "bootstrap_reservation_insert_reserved",
        "CREATE TRIGGER bootstrap_reservation_insert_reserved BEFORE INSERT ON bootstrap_reservations WHEN NEW.reservation_state != 'RESERVED' OR NEW.attempt_count != 0 BEGIN SELECT RAISE(ABORT, 'bootstrap reservation must begin reserved'); END",
    ),
    (
        "bootstrap_reservation_through_expiry",
        "CREATE TRIGGER bootstrap_reservation_through_expiry BEFORE DELETE ON bootstrap_reservations WHEN OLD.expiry_unix_microseconds > (SELECT observed_at FROM bootstrap_last_observed_clock WHERE id = 1) BEGIN SELECT RAISE(ABORT, 'bootstrap reservation remains through expiry'); END",
    ),
    (
        "bootstrap_tombstone_through_expiry",
        "CREATE TRIGGER bootstrap_tombstone_through_expiry BEFORE DELETE ON bootstrap_reservation_tombstones WHEN OLD.expiry_unix_microseconds > (SELECT observed_at FROM bootstrap_last_observed_clock WHERE id = 1) BEGIN SELECT RAISE(ABORT, 'bootstrap tombstone remains through expiry'); END",
    ),
    (
        "bootstrap_tombstone_immutable",
        "CREATE TRIGGER bootstrap_tombstone_immutable BEFORE UPDATE ON bootstrap_reservation_tombstones BEGIN SELECT RAISE(ABORT, 'bootstrap tombstone is immutable'); END",
    ),
    (
        "bootstrap_clock_monotonic",
        "CREATE TRIGGER bootstrap_clock_monotonic BEFORE UPDATE ON bootstrap_last_observed_clock WHEN NEW.id != OLD.id OR NEW.observed_at < OLD.observed_at BEGIN SELECT RAISE(ABORT, 'bootstrap clock rollback'); END",
    ),
    (
        "bootstrap_clock_permanent",
        "CREATE TRIGGER bootstrap_clock_permanent BEFORE DELETE ON bootstrap_last_observed_clock BEGIN SELECT RAISE(ABORT, 'bootstrap clock is permanent'); END",
    ),
];

fn apply_v17_migration(conn: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V17)?;
    install_missing_v12_fence_triggers(&tx)?;
    for (_, sql) in V17_TRIGGERS {
        tx.execute_batch(sql)?;
    }
    tx.execute("INSERT INTO schema_version (version) VALUES (17)", [])?;
    tx.commit()
}

fn released_v17_matches(conn: &Connection, version: i64) -> SqliteResult<bool> {
    Ok(version == 17
        && v17_marker_matches(conn)?
        && released_v17_base_matches_with_additional_triggers(conn, version, &[])?
        && v17_catalog_matches(conn)?)
}

/// Validates the immutable V17 bootstrap boundary before successor migrations
/// add their own tables and triggers.
pub(super) fn released_v17_base_matches_with_additional_triggers(
    conn: &Connection,
    version: i64,
    additional_triggers: &[&str],
) -> SqliteResult<bool> {
    if version < 17 || !v17_inherited_v16_schema_matches(conn)? {
        return Ok(false);
    }
    Ok(
        table_sql_matches_migration(conn, "bootstrap_reservations", MIGRATION_V17)?
            && table_sql_matches_migration(
                conn,
                "bootstrap_reservation_tombstones",
                MIGRATION_V17,
            )?
            && table_sql_matches_migration(conn, "bootstrap_last_observed_clock", MIGRATION_V17)?
            && v17_index_matches(conn)?
            && v17_inherited_trigger_bodies_match(conn)?
            && v17_triggers_match_with_additional(conn, additional_triggers)?
            && v17_clock_matches(conn)?,
    )
}

fn v17_inherited_v16_schema_matches(conn: &Connection) -> SqliteResult<bool> {
    let v12 = provider_v12_core_matches(conn)?;
    let v13 = v13_unchanged_tables_match(conn)?;
    let v14 = provider_schema::v14_base_matches(conn, v12, v13)?;
    let v15 = provider_schema::v15_matches(conn, 15, v14)?;
    Ok(v15
        && table_sql_matches_migration(conn, "provider_credential_versions", MIGRATION_V16)?
        && table_sql_matches_migration(conn, "provider_credential_effect_bindings", MIGRATION_V16)?
        && table_sql_matches_migration(
            conn,
            "provider_credential_clock_high_water",
            MIGRATION_V16,
        )?
        && table_sql_matches_migration(conn, "provider_credential_provisions", MIGRATION_V16)?
        && index_sql_matches_v16(conn)?)
}

fn v17_inherited_trigger_bodies_match(conn: &Connection) -> SqliteResult<bool> {
    for table in authoritative_v12_tables(conn)? {
        for operation in ["insert", "update", "delete"] {
            let (name, expected) = v12_fence_trigger(&table, operation);
            if !trigger_sql_matches(conn, &name, &expected)? {
                return Ok(false);
            }
        }
    }
    for (name, _, expected) in v12_guard_triggers() {
        if !trigger_sql_matches(conn, name, expected)? {
            return Ok(false);
        }
    }
    for (name, expected) in V16_TRIGGERS {
        if !trigger_sql_matches(conn, name, expected)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn v17_marker_matches(conn: &Connection) -> SqliteResult<bool> {
    let marker: (i64, i64, i64, i64) = conn.query_row(
        "SELECT COUNT(*), MIN(version), MAX(version), SUM(version) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(marker == (17, 1, 17, 153))
}

fn v17_index_matches(conn: &Connection) -> SqliteResult<bool> {
    let actual: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='bootstrap_reservation_unexpired'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let expected = MIGRATION_V17
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with("CREATE INDEX bootstrap_reservation_unexpired"));
    Ok(actual.is_some_and(|actual| {
        expected.is_some_and(|expected| normalize_ddl(&actual) == normalize_ddl(expected))
    }))
}

fn v17_triggers_match_with_additional(
    conn: &Connection,
    additional_triggers: &[&str],
) -> SqliteResult<bool> {
    let expected_count = authoritative_v12_tables(conn)?.len() * 3
        + v12_guard_triggers().len()
        + V16_TRIGGERS.len()
        + V17_TRIGGERS.len()
        + additional_triggers.len();
    let actual_count: usize = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'",
        [],
        |row| row.get(0),
    )?;
    if actual_count != expected_count {
        return Ok(false);
    }
    V17_TRIGGERS
        .iter()
        .try_fold(true, |matches, (name, expected)| {
            Ok(matches && trigger_sql_matches(conn, name, expected)?)
        })
}

fn v17_clock_matches(conn: &Connection) -> SqliteResult<bool> {
    let clock: Option<(i64, i64)> = conn
        .query_row(
            "SELECT id, observed_at FROM bootstrap_last_observed_clock",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(clock.is_some_and(|(id, observed)| id == 1 && observed >= 0))
}

fn v17_catalog_matches(conn: &Connection) -> SqliteResult<bool> {
    let mut tables = RELEASED_V13_TABLES.to_vec();
    tables.extend([
        "provider_effect_starts",
        "provider_credential_versions",
        "provider_credential_clock_high_water",
        "provider_credential_provisions",
        "provider_credential_effect_bindings",
        "bootstrap_reservations",
        "bootstrap_reservation_tombstones",
        "bootstrap_last_observed_clock",
    ]);
    let mut indexes = RELEASED_V12_EXPLICIT_INDEXES.to_vec();
    indexes.extend([
        "provider_credential_one_active",
        "provider_credential_one_pending_provision",
        "bootstrap_reservation_unexpired",
    ]);
    released_catalog_matches_with_indexes(conn, &tables, &indexes)
}
