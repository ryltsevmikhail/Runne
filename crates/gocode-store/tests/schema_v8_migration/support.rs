
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

fn released_v8_db() -> Connection {
    let conn = fresh_v8_db();
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
