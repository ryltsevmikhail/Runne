const MIGRATION_V16: &str = r#"
CREATE TABLE provider_credential_versions (
    provider_id TEXT NOT NULL CHECK(length(provider_id) BETWEEN 1 AND 128),
    credential_version INTEGER NOT NULL CHECK(credential_version > 0),
    ref_digest BLOB NOT NULL CHECK(length(ref_digest) = 32),
    lifecycle_state TEXT NOT NULL
        CHECK(lifecycle_state IN ('PREPARED', 'ACTIVE', 'RETIRED', 'GC_CLAIMED', 'DELETED')),
    lease_owner BLOB CHECK(lease_owner IS NULL OR length(lease_owner) = 16),
    lease_expires_at INTEGER,
    lease_fencing_token INTEGER CHECK(lease_fencing_token IS NULL OR lease_fencing_token > 0),
    revocation_fence INTEGER NOT NULL DEFAULT 0 CHECK(revocation_fence >= 0),
    tombstone_digest BLOB CHECK(tombstone_digest IS NULL OR length(tombstone_digest) = 32),
    PRIMARY KEY(provider_id, credential_version),
    UNIQUE(ref_digest),
    CHECK(
        (lifecycle_state = 'PREPARED' AND lease_owner IS NULL
            AND lease_expires_at IS NULL AND lease_fencing_token IS NULL
            AND revocation_fence = 0 AND tombstone_digest IS NULL)
        OR
        (lifecycle_state = 'ACTIVE'
            AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL
            AND lease_fencing_token IS NOT NULL AND tombstone_digest IS NULL
            AND revocation_fence < lease_fencing_token)
        OR
        (lifecycle_state IN ('RETIRED', 'GC_CLAIMED')
            AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL
            AND lease_fencing_token IS NOT NULL AND tombstone_digest IS NULL
            AND revocation_fence >= lease_fencing_token)
        OR
        (lifecycle_state = 'DELETED' AND lease_owner IS NOT NULL
            AND lease_expires_at IS NOT NULL AND lease_fencing_token IS NOT NULL
            AND tombstone_digest IS NOT NULL
            AND revocation_fence >= lease_fencing_token)
    )
);
CREATE UNIQUE INDEX provider_credential_one_active
    ON provider_credential_versions(provider_id)
    WHERE lifecycle_state = 'ACTIVE';
CREATE TABLE provider_credential_clock_high_water (
    provider_id TEXT NOT NULL PRIMARY KEY
        CHECK(length(provider_id) BETWEEN 1 AND 128),
    observed_at INTEGER NOT NULL CHECK(observed_at >= 0)
);
CREATE TABLE provider_credential_provisions (
    operation_id BLOB NOT NULL PRIMARY KEY CHECK(length(operation_id) = 16),
    provider_id TEXT NOT NULL CHECK(length(provider_id) BETWEEN 1 AND 128),
    credential_version INTEGER NOT NULL CHECK(credential_version > 0),
    ref_digest BLOB NOT NULL CHECK(length(ref_digest) = 32),
    provision_state TEXT NOT NULL
        CHECK(provision_state IN ('PREPARED', 'NATIVE_CREATED', 'ACTIVATED')),
    UNIQUE(provider_id, credential_version),
    FOREIGN KEY(provider_id, credential_version)
        REFERENCES provider_credential_versions(provider_id, credential_version)
);
CREATE UNIQUE INDEX provider_credential_one_pending_provision
    ON provider_credential_provisions(provider_id)
    WHERE provision_state != 'ACTIVATED';
CREATE TABLE provider_credential_effect_bindings (
    dispatch_attempt_id BLOB NOT NULL PRIMARY KEY
        REFERENCES provider_effect_starts(dispatch_attempt_id),
    provider_id TEXT NOT NULL,
    credential_version INTEGER NOT NULL CHECK(credential_version > 0),
    ref_digest BLOB NOT NULL CHECK(length(ref_digest) = 32),
    lease_owner BLOB NOT NULL CHECK(length(lease_owner) = 16),
    lease_expires_at INTEGER NOT NULL,
    lease_fencing_token INTEGER NOT NULL CHECK(lease_fencing_token > 0),
    FOREIGN KEY(provider_id, credential_version)
        REFERENCES provider_credential_versions(provider_id, credential_version)
);
"#;

const V16_TRIGGERS: [(&str, &str); 8] = [
    (
        "provider_credential_transition_order",
        "CREATE TRIGGER provider_credential_transition_order BEFORE UPDATE ON provider_credential_versions WHEN NEW.revocation_fence < OLD.revocation_fence OR NOT (NEW.lifecycle_state = OLD.lifecycle_state OR (OLD.lifecycle_state = 'PREPARED' AND NEW.lifecycle_state = 'ACTIVE') OR (OLD.lifecycle_state = 'ACTIVE' AND NEW.lifecycle_state = 'RETIRED' AND NEW.revocation_fence >= OLD.lease_fencing_token) OR (OLD.lifecycle_state = 'RETIRED' AND NEW.lifecycle_state = 'GC_CLAIMED' AND OLD.revocation_fence >= OLD.lease_fencing_token) OR (OLD.lifecycle_state = 'GC_CLAIMED' AND NEW.lifecycle_state = 'DELETED')) BEGIN SELECT RAISE(ABORT, 'invalid credential lifecycle transition'); END",
    ),
    (
        "provider_credential_identity_immutable",
        "CREATE TRIGGER provider_credential_identity_immutable BEFORE UPDATE ON provider_credential_versions WHEN OLD.lifecycle_state = 'DELETED' OR NEW.provider_id != OLD.provider_id OR NEW.credential_version != OLD.credential_version OR NEW.ref_digest != OLD.ref_digest OR (OLD.lifecycle_state != 'PREPARED' AND (NEW.lease_owner != OLD.lease_owner OR NEW.lease_expires_at != OLD.lease_expires_at OR NEW.lease_fencing_token != OLD.lease_fencing_token)) BEGIN SELECT RAISE(ABORT, 'credential identity, lease, or tombstone is immutable'); END",
    ),
    (
        "provider_credential_insert_prepared",
        "CREATE TRIGGER provider_credential_insert_prepared BEFORE INSERT ON provider_credential_versions WHEN NEW.lifecycle_state != 'PREPARED' BEGIN SELECT RAISE(ABORT, 'credential version must begin prepared'); END",
    ),
    (
        "provider_credential_tombstone_permanent",
        "CREATE TRIGGER provider_credential_tombstone_permanent BEFORE DELETE ON provider_credential_versions BEGIN SELECT RAISE(ABORT, 'credential tombstone is permanent'); END",
    ),
    (
        "provider_credential_provision_order",
        "CREATE TRIGGER provider_credential_provision_order BEFORE UPDATE ON provider_credential_provisions WHEN NEW.operation_id != OLD.operation_id OR NEW.provider_id != OLD.provider_id OR NEW.credential_version != OLD.credential_version OR NEW.ref_digest != OLD.ref_digest OR NOT (NEW.provision_state = OLD.provision_state OR (OLD.provision_state = 'PREPARED' AND NEW.provision_state = 'NATIVE_CREATED') OR (OLD.provision_state = 'NATIVE_CREATED' AND NEW.provision_state = 'ACTIVATED')) BEGIN SELECT RAISE(ABORT, 'invalid credential provision transition'); END",
    ),
    (
        "provider_credential_provision_permanent",
        "CREATE TRIGGER provider_credential_provision_permanent BEFORE DELETE ON provider_credential_provisions BEGIN SELECT RAISE(ABORT, 'credential provision identity is permanent'); END",
    ),
    (
        "provider_credential_clock_monotonic",
        "CREATE TRIGGER provider_credential_clock_monotonic BEFORE UPDATE ON provider_credential_clock_high_water WHEN NEW.provider_id != OLD.provider_id OR NEW.observed_at < OLD.observed_at BEGIN SELECT RAISE(ABORT, 'credential clock rollback'); END",
    ),
    (
        "provider_credential_clock_permanent",
        "CREATE TRIGGER provider_credential_clock_permanent BEFORE DELETE ON provider_credential_clock_high_water BEGIN SELECT RAISE(ABORT, 'credential clock high-water is permanent'); END",
    ),
];

fn apply_v16_migration(conn: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V16)?;
    install_missing_v12_fence_triggers(&tx)?;
    for (_, sql) in V16_TRIGGERS {
        tx.execute_batch(sql)?;
    }
    tx.execute("INSERT INTO schema_version (version) VALUES (16)", [])?;
    tx.commit()
}

fn is_released_provider_v16(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 16 || !v16_marker_matches(conn)? {
        return Ok(false);
    }
    let v12 = provider_v12_core_matches(conn)?;
    let v13 = v13_unchanged_tables_match(conn)?;
    let v14 = provider_schema::v14_base_matches(conn, v12, v13)?;
    Ok(provider_schema::v15_matches(conn, 15, v14)?
        && table_sql_matches_migration(conn, "provider_credential_versions", MIGRATION_V16)?
        && table_sql_matches_migration(
            conn,
            "provider_credential_effect_bindings",
            MIGRATION_V16,
        )?
        && table_sql_matches_migration(
            conn,
            "provider_credential_clock_high_water",
            MIGRATION_V16,
        )?
        && table_sql_matches_migration(conn, "provider_credential_provisions", MIGRATION_V16)?
        && index_sql_matches_v16(conn)?
        && v16_triggers_match(conn)?
        && v16_catalog_matches(conn)?)
}

fn v16_marker_matches(conn: &Connection) -> SqliteResult<bool> {
    let marker: (i64, i64, i64, i64) = conn.query_row(
        "SELECT COUNT(*), MIN(version), MAX(version), SUM(version) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(marker == (16, 1, 16, 136))
}

fn one_index_matches_v16(conn: &Connection, name: &str) -> SqliteResult<bool> {
    let actual: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    let expected = MIGRATION_V16
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with(&format!("CREATE UNIQUE INDEX {name}")));
    Ok(actual.is_some_and(|actual| {
        expected.is_some_and(|expected| normalize_ddl(&actual) == normalize_ddl(expected))
    }))
}

fn index_sql_matches_v16(conn: &Connection) -> SqliteResult<bool> {
    one_index_matches_v16(conn, "provider_credential_one_active")?
        .then(|| one_index_matches_v16(conn, "provider_credential_one_pending_provision"))
        .transpose()
        .map(|matched| matched == Some(true))
}

fn v16_triggers_match(conn: &Connection) -> SqliteResult<bool> {
    let tables = authoritative_v12_tables(conn)?;
    let expected_count = tables.len() * 3 + v12_guard_triggers().len() + V16_TRIGGERS.len();
    let actual_count: usize = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'",
        [],
        |row| row.get(0),
    )?;
    if actual_count != expected_count {
        return Ok(false);
    }
    for table in tables {
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

fn trigger_sql_matches(conn: &Connection, name: &str, expected: &str) -> SqliteResult<bool> {
    let actual: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(actual.is_some_and(|actual| normalize_sql(&actual) == normalize_sql(expected)))
}

fn v16_catalog_matches(conn: &Connection) -> SqliteResult<bool> {
    let mut tables = RELEASED_V13_TABLES.to_vec();
    tables.extend([
        "provider_effect_starts",
        "provider_credential_versions",
        "provider_credential_clock_high_water",
        "provider_credential_provisions",
        "provider_credential_effect_bindings",
    ]);
    let mut indexes = RELEASED_V12_EXPLICIT_INDEXES.to_vec();
    indexes.extend([
        "provider_credential_one_active",
        "provider_credential_one_pending_provision",
    ]);
    released_catalog_matches_with_indexes(conn, &tables, &indexes)
}
