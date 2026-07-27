//! Integration tests for schema v8: daemon tables, authority ID, and startup purge.

use gocode_store::schema::{
    CURRENT_SCHEMA_VERSION, apply_migrations, ensure_authority_id, generate_authority_id,
    purge_replay_subscriptions, read_authority_id,
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
    let conn = Connection::open_in_memory().unwrap();

    // Simulate a v6 database: create schema_version and insert versions 1-6
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .unwrap();

    for v in 1..=6 {
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            params![v],
        )
        .unwrap();
    }

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
    assert_eq!(version, 8);
}
