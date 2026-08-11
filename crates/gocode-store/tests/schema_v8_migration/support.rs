// Integration tests for schema v8: daemon tables, authority ID, and startup purge.

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

fn drop_v13_provider_execution(conn: &Connection) {
    conn.execute_batch(
        "DROP TABLE bootstrap_reservation_tombstones;
         DROP TABLE bootstrap_reservations;
         DROP TABLE bootstrap_last_observed_clock;
         DROP TABLE provider_credential_effect_bindings;
         DROP TABLE provider_credential_provisions;
         DROP TABLE provider_credential_clock_high_water;
         DROP TABLE provider_credential_versions;
         DROP TABLE provider_effect_starts;
         DROP TABLE provider_terminal_outbox;
         DROP TABLE provider_accounting_settlements;
         DROP TABLE provider_stream_journal;
         DROP TABLE provider_poll_flights;
         DROP TABLE provider_encryption_nonces;
         DROP TABLE provider_journal_key_refs;
         DROP TABLE provider_budget_reservations;
         DROP TABLE provider_execution_admissions;
         DROP TABLE provider_runtime_authority_state;",
    )
    .unwrap();
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
