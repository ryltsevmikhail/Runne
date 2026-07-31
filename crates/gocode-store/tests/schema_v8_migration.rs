//! Integration tests for schema v8: daemon tables, authority ID, and startup purge.

use gocode_store::schema::{
    CURRENT_SCHEMA_VERSION, apply_migrations, ensure_authority_id, ensure_event_log_lineage_id,
    generate_authority_id, purge_replay_subscriptions, read_authority_id,
};
use rusqlite::{Connection, params};

// ── helpers ─────────────────────────────────────────────────────────────

fn table_exists(conn: &Connection, name: &str) -> bool {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .unwrap();
    count > 0
}

fn fresh_v8_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    apply_migrations(&conn).unwrap();
    conn
}

fn drop_v12_fences(conn: &Connection) {
    let triggers = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'trigger' AND name LIKE 'schema_v12_%'",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for trigger in triggers {
        conn.execute_batch(&format!("DROP TRIGGER \"{trigger}\";"))
            .unwrap();
    }
    conn.execute_batch(
        "DROP TABLE schema_upgrade_write_latch;
         DROP TABLE schema_upgrade_fence;",
    )
    .unwrap();
}

fn released_v8_db() -> Connection {
    let conn = fresh_v8_db();
    drop_v12_fences(&conn);
    conn.execute_batch(
        "DROP TABLE provider_effect_authorities;
         DROP TABLE provider_dispatch_attempts;
         DROP TABLE provider_prepared_requests;
         DROP TABLE schema_lineage;
         DROP TABLE consumption_intents;
         DROP TABLE verification_evidence;
         DELETE FROM schema_version WHERE version >= 9;",
    )
    .unwrap();
    conn
}

fn schema_objects(conn: &Connection) -> Vec<(String, String)> {
    conn.prepare("SELECT type, name FROM sqlite_master ORDER BY type, name")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

// ── v8 migration ────────────────────────────────────────────────────────

#[test]
fn v8_migration_creates_tables() {
    let conn = fresh_v8_db();

    for table in ["_authority", "_daemon_info", "_replay_subscriptions"] {
        assert!(table_exists(&conn, table), "missing v8 table {table}");
    }

    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
}

#[test]
fn event_log_lineage_is_persisted_as_stable_uuid_v7() {
    let conn = fresh_v8_db();

    let first = ensure_event_log_lineage_id(&conn).unwrap();
    let second = ensure_event_log_lineage_id(&conn).unwrap();

    assert_eq!(first, second);
    let parsed = uuid::Uuid::from_bytes(first.into_bytes());
    assert_eq!(parsed.get_version_num(), 7);
    assert_eq!(parsed.get_variant(), uuid::Variant::RFC4122);
}

// ── authority ID ────────────────────────────────────────────────────────

#[test]
fn generate_authority_id_unique() {
    let id1 = generate_authority_id();
    let id2 = generate_authority_id();
    assert_ne!(id1, id2);
}

#[test]
fn ensure_authority_id_idempotent() {
    let conn = fresh_v8_db();
    let id = [0xAB; 16];

    ensure_authority_id(&conn, &id).unwrap();
    ensure_authority_id(&conn, &id).unwrap(); // double call must not panic

    let read = read_authority_id(&conn).unwrap();
    assert_eq!(read, Some(id));
}

#[test]
fn read_authority_id_none() {
    let conn = fresh_v8_db();

    let result = read_authority_id(&conn).unwrap();
    assert_eq!(result, None);
}

#[test]
fn read_authority_id_after_insert() {
    let conn = fresh_v8_db();
    let id = [0xCD; 16];

    ensure_authority_id(&conn, &id).unwrap();

    let result = read_authority_id(&conn).unwrap();
    assert_eq!(result, Some(id));
}

#[test]
fn authority_check_constraint_enforced() {
    let conn = fresh_v8_db();

    // id != 1 must fail
    let result = conn.execute(
        "INSERT INTO _authority (id, authority_id) VALUES (2, ?1)",
        params![[0u8; 16].as_slice()],
    );
    assert!(result.is_err(), "id=2 should be rejected by CHECK (id = 1)");

    // authority_id with wrong length must fail
    let result = conn.execute(
        "INSERT INTO _authority (id, authority_id) VALUES (1, ?1)",
        params![[0u8; 8].as_slice()],
    );
    assert!(
        result.is_err(),
        "authority_id length 8 should be rejected by CHECK (length = 16)"
    );
}

// ── startup purge ───────────────────────────────────────────────────────

#[test]
fn startup_purge_clears_subscriptions() {
    let conn = fresh_v8_db();

    // Insert a valid replay subscription row
    conn.execute(
        "INSERT INTO _replay_subscriptions (
            session_id, principal_id, session_generation, authority_id,
            authorization_epoch, aggregate_type, aggregate_id, retention_generation,
            high_water_position, state, high_water_ref, created_at
        ) VALUES (
            ?1, 'principal-1', 1, ?2, 0, 1, ?3, 0, 0,
            'live', ?4, datetime('now')
        )",
        params![
            [0x01u8; 16].as_slice(),
            [0x02u8; 16].as_slice(),
            [0x03u8; 16].as_slice(),
            [0x04u8; 16].as_slice(),
        ],
    )
    .unwrap();

    // Verify row exists before purge
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);

    // Purge
    purge_replay_subscriptions(&conn).unwrap();

    // Verify table is empty
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

// ── v6 → v8 upgrade path ────────────────────────────────────────────────

#[test]
fn v6_to_v8_migration() {
    let conn = fresh_v8_db();
    drop_v12_fences(&conn);
    conn.execute_batch(
        "DROP TABLE provider_effect_authorities;
         DROP TABLE provider_dispatch_attempts;
         DROP TABLE provider_prepared_requests;
         DROP TABLE schema_lineage;
         DROP TABLE consumption_intents;
         DROP TABLE verification_evidence;
         DROP TABLE _replay_subscriptions;
         DROP TABLE _daemon_info;
         DROP TABLE _authority;
         DROP TABLE security_permit_claims;
         DROP TABLE security_audit_pre_effect;
         DROP TABLE security_budget_consumptions;
         DROP TABLE security_authorization_decisions;
         DROP TABLE security_dispatch_intents;
         DELETE FROM schema_version WHERE version >= 7;",
    )
    .unwrap();

    // Apply remaining migrations (v7, v8)
    apply_migrations(&conn).unwrap();

    // Verify v7 tables
    for table in [
        "security_dispatch_intents",
        "security_authorization_decisions",
        "security_budget_consumptions",
        "security_audit_pre_effect",
        "security_permit_claims",
    ] {
        assert!(table_exists(&conn, table), "missing v7 table {table}");
    }

    // Verify v8 tables
    for table in ["_authority", "_daemon_info", "_replay_subscriptions"] {
        assert!(table_exists(&conn, table), "missing v8 table {table}");
    }

    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
}

// ── released V8 → strict V9 lineage ─────────────────────────────────────

#[test]
fn released_v8_upgrades_to_strict_v9_and_rejects_invalid_values() {
    let conn = released_v8_db();

    apply_migrations(&conn).unwrap();

    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    assert_eq!(CURRENT_SCHEMA_VERSION, 12);
    assert!(table_exists(&conn, "verification_evidence"));
    assert!(table_exists(&conn, "consumption_intents"));
    assert!(!table_exists(&conn, "verification_evidence_v10"));
    assert!(!table_exists(&conn, "consumption_intents_v11"));

    let digest = [0xA5_u8; 32];
    assert!(
        conn.execute(
            "INSERT INTO consumption_intents VALUES (?1, 'key', 'Reserved', ?2, ?2, ?2)",
            params![[0_u8; 15].as_slice(), digest.as_slice()],
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "INSERT INTO consumption_intents VALUES (?1, 'key-2', 'Unknown', ?2, ?2, ?2)",
            params![[0_u8; 16].as_slice(), digest.as_slice()],
        )
        .is_err()
    );
    assert!(conn
        .execute(
            "INSERT INTO verification_evidence VALUES (?1, ?1, ?1, ?2, 0, 0, ?2, '', 'store', 'producer', 0, 'sqlite')",
            params![[0_u8; 16].as_slice(), digest.as_slice()],
        )
        .is_err());
    assert!(conn
        .execute(
            "INSERT INTO verification_evidence VALUES (?1, ?1, ?1, ?2, 6, 0, ?2, 'blob:test', 'store', 'producer', 0, 'sqlite')",
            params![[0_u8; 16].as_slice(), digest.as_slice()],
        )
        .is_err());
}

#[test]
fn failed_v8_to_v9_upgrade_is_atomic() {
    let conn = released_v8_db();
    let before = schema_objects(&conn);
    conn.execute_batch(
        "CREATE TRIGGER reject_v9_marker BEFORE INSERT ON schema_version
         WHEN NEW.version = 9
         BEGIN
             SELECT RAISE(ABORT, 'test V9 marker rejection');
         END;",
    )
    .unwrap();

    assert!(apply_migrations(&conn).is_err());

    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 8);
    assert!(!table_exists(&conn, "verification_evidence"));
    assert!(!table_exists(&conn, "consumption_intents"));
    assert!(!table_exists(&conn, "schema_lineage"));

    let mut expected = before;
    expected.push(("trigger".to_owned(), "reject_v9_marker".to_owned()));
    expected.sort_unstable();
    assert_eq!(schema_objects(&conn), expected);
}

#[test]
fn candidate_only_markers_are_rejected_without_mutation() {
    for marker in [9, 10, 11] {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             CREATE TABLE candidate_only (value TEXT NOT NULL);",
        )
        .unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (?1)", [marker])
            .unwrap();
        conn.execute("INSERT INTO candidate_only VALUES ('unchanged')", [])
            .unwrap();
        let before = schema_objects(&conn);

        let error = apply_migrations(&conn).unwrap_err();
        assert!(matches!(error, rusqlite::Error::InvalidQuery));
        assert_eq!(schema_objects(&conn), before);
        assert_eq!(
            conn.query_row("SELECT value FROM candidate_only", [], |row| row
                .get::<_, String>(0))
                .unwrap(),
            "unchanged"
        );
    }
}
