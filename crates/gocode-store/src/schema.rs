//! Database schema — DDL, migrations, and startup PRAGMA gates.
//!
//! The schema consists of:
//! - `schema_version` — tracks applied migrations
//! - `event_log_state` — singleton row for global position counter
//! - `aggregate_streams` — per-aggregate stream metadata
//! - `events` — committed event rows
//! - `command_receipts` — idempotency receipt store

use rand::RngCore;
use rand::rngs::OsRng;
use std::path::Path;

use rusqlite::{Connection, OpenFlags, Result as SqliteResult};

/// Current schema version. Increment when adding new DDL migrations.
pub const CURRENT_SCHEMA_VERSION: i64 = 9;

/// Reject unsupported existing database schemas without changing the file.
///
/// File-backed verification stores call this before enabling WAL or applying
/// migrations, so an unsupported future or candidate schema remains untouched.
pub fn preflight_existing_file(db_path: &Path) -> SqliteResult<()> {
    if !db_path.exists() {
        return Ok(());
    }

    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let user_version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if user_version > CURRENT_SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }

    let has_version_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version')",
        [],
        |row| row.get(0),
    )?;
    if !has_version_table {
        return Ok(());
    }

    let schema_version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if schema_version > CURRENT_SCHEMA_VERSION
        || (schema_version >= 9 && !is_released_strict_v9(&conn, schema_version)?)
    {
        return Err(rusqlite::Error::InvalidQuery);
    }

    Ok(())
}

/// Apply all schema migrations up to [`CURRENT_SCHEMA_VERSION`].
///
/// Idempotent — only runs migrations not yet applied.
pub fn apply_migrations(conn: &Connection) -> SqliteResult<()> {
    let has_version_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version')",
        [],
        |row| row.get(0),
    )?;
    if has_version_table {
        let existing_version: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )?;
        if existing_version > 8 && !is_released_strict_v9(conn, existing_version)? {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;

    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if current_version < 1 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V1)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (1)", [])?;
        tx.commit()?;
    }

    if current_version < 2 {
        // Keep DDL, V1 backfill, and the version marker in one transaction.
        // `Transaction` rolls back on drop if any ALTER or rename fails.
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V2)?;
        tx.execute(
            "UPDATE events
             SET correlation_id = taskrun_id,
                 correlation_type = 1,
                 integrity_profile = 1",
            [],
        )?;
        tx.execute("INSERT INTO schema_version (version) VALUES (2)", [])?;
        tx.commit()?;
    }

    if current_version < 3 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V3)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (3)", [])?;
        tx.commit()?;
    }

    if current_version < 4 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V4)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (4)", [])?;
        tx.commit()?;
    }

    if current_version < 5 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V5)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (5)", [])?;
        tx.commit()?;
    }

    if current_version < 6 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V6)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (6)", [])?;
        tx.commit()?;
    }

    if current_version < 7 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V7)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (7)", [])?;
        tx.commit()?;
    }

    if current_version < 8 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V8)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (8)", [])?;
        tx.commit()?;
    }

    if current_version < 9 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V9)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (9)", [])?;
        tx.commit()?;
    }

    Ok(())
}

fn is_released_strict_v9(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != CURRENT_SCHEMA_VERSION {
        return Ok(false);
    }
    let has_lineage_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_lineage')",
        [],
        |row| row.get(0),
    )?;
    if !has_lineage_table {
        return Ok(false);
    }
    let provenance_matches: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_lineage WHERE schema_version = 9 AND provenance = 'released-v8-to-strict-v9')",
        [],
        |row| row.get(0),
    )?;
    if !provenance_matches {
        return Ok(false);
    }
    for (table, required_fragments) in [
        (
            "consumption_intents",
            [
                "length(intent_id) = 16",
                "idempotency_key TEXT NOT NULL UNIQUE",
                "length(integrity_digest) = 32",
            ]
            .as_slice(),
        ),
        (
            "verification_evidence",
            [
                "length(evidence_id) = 16",
                "layer INTEGER NOT NULL CHECK(layer IN (0, 1, 2, 3, 4, 5))",
                "length(verified_by) > 0",
            ]
            .as_slice(),
        ),
    ] {
        let schema_sql: Option<String> = conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )?;
        if !schema_sql.is_some_and(|sql| {
            required_fragments
                .iter()
                .all(|fragment| sql.contains(fragment))
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Run startup gates: integrity check, FK check, and PRAGMA profile
/// verification.
///
/// Fails closed (returns an error) if any check fails.
pub fn run_startup_gates(conn: &Connection, _db_path: &str) -> SqliteResult<()> {
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut foreign_key_check = conn.prepare("PRAGMA foreign_key_check")?;
    if foreign_key_check.exists([])? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let schema_version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if schema_version != CURRENT_SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }

    // PRAGMA profile verification
    verify_pragma(conn, "journal_mode", "wal")?;
    verify_pragma(conn, "synchronous", "2")?; // FULL = 2
    verify_pragma(conn, "foreign_keys", "1")?;
    #[cfg(target_os = "macos")]
    verify_pragma(conn, "fullfsync", "1")?;

    // Set file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in &["", "-wal", "-shm"] {
            let path = format!("{}{}", _db_path, suffix);
            if let Ok(meta) = std::fs::metadata(&path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&path, perms)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            }
        }
    }

    Ok(())
}

/// Verify a PRAGMA value matches the expected value.
fn verify_pragma(conn: &Connection, pragma: &str, expected: &str) -> SqliteResult<()> {
    let sql = format!("PRAGMA {};", pragma);
    // PRAGMAs return either text or integer — try integer first, then text
    let actual: String = conn.query_row(&sql, [], |row| {
        row.get::<_, String>(0).or_else(|_| {
            let val: i32 = row.get(0)?;
            Ok(val.to_string())
        })
    })?;
    if actual != expected {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
            Some(format!(
                "PRAGMA {} = '{}', expected '{}'",
                pragma, actual, expected
            )),
        ));
    }
    Ok(())
}

// ── Migration V1: initial schema ─────────────────────────────────────────

const MIGRATION_V1: &str = r#"
CREATE TABLE event_log_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_global_position INTEGER NOT NULL DEFAULT 1
);

INSERT INTO event_log_state (singleton, next_global_position) VALUES (1, 1);

CREATE TABLE task_run_streams (
    taskrun_id BLOB PRIMARY KEY,
    current_version INTEGER NOT NULL DEFAULT 0,
    last_event_id BLOB,
    last_timestamp INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE events (
    event_id BLOB PRIMARY KEY,
    taskrun_id BLOB NOT NULL REFERENCES task_run_streams(taskrun_id),
    sequence INTEGER NOT NULL,
    global_position INTEGER NOT NULL UNIQUE,
    timestamp INTEGER NOT NULL,
    aggregate_type INTEGER NOT NULL,
    sensitivity INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    causation_id BLOB,
    command_id BLOB NOT NULL,
    idempotency_key BLOB NOT NULL,
    actor BLOB NOT NULL,
    payload BLOB NOT NULL,
    integrity_digest BLOB NOT NULL,
    UNIQUE(taskrun_id, sequence)
);

CREATE INDEX idx_events_taskrun_sequence
    ON events(taskrun_id, sequence);

CREATE TABLE command_receipts (
    command_id BLOB NOT NULL,
    idempotency_scope_bytes BLOB NOT NULL,
    idempotency_key BLOB NOT NULL,
    fingerprint BLOB NOT NULL,
    command_outcome BLOB NOT NULL,
    committed_at INTEGER NOT NULL,
    UNIQUE(command_id),
    UNIQUE(idempotency_scope_bytes, idempotency_key)
);

CREATE INDEX idx_receipts_scope_key
    ON command_receipts(idempotency_scope_bytes, idempotency_key);
"#;

// ── Migration V2: correlation_id + aggregate_streams ─────────────────────

const MIGRATION_V2: &str = r#"
ALTER TABLE events ADD COLUMN correlation_id BLOB NOT NULL DEFAULT x'';
ALTER TABLE events ADD COLUMN correlation_type INTEGER NOT NULL DEFAULT 1;
ALTER TABLE events ADD COLUMN integrity_profile INTEGER NOT NULL DEFAULT 1;

ALTER TABLE task_run_streams RENAME TO aggregate_streams;
"#;

// ── Migration V3: typed aggregate stream identity ───────────────────────

const MIGRATION_V3: &str = r#"
CREATE TABLE aggregate_streams_v3 (
    aggregate_type INTEGER NOT NULL CHECK(aggregate_type IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    current_version INTEGER NOT NULL DEFAULT 0 CHECK(current_version >= 0),
    last_event_id BLOB CHECK(last_event_id IS NULL OR length(last_event_id) = 16),
    last_timestamp INTEGER,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(aggregate_type, aggregate_id)
);

INSERT INTO aggregate_streams_v3
    (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
SELECT 1, taskrun_id, current_version, last_event_id, last_timestamp, created_at
FROM aggregate_streams;

CREATE TABLE events_v3 (
    event_id BLOB PRIMARY KEY CHECK(length(event_id) = 16),
    aggregate_type INTEGER NOT NULL CHECK(aggregate_type IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    global_position INTEGER NOT NULL UNIQUE CHECK(global_position > 0),
    timestamp INTEGER NOT NULL,
    sensitivity INTEGER NOT NULL,
    schema_version INTEGER NOT NULL CHECK(schema_version BETWEEN 0 AND 4294967295),
    causation_id BLOB CHECK(causation_id IS NULL OR length(causation_id) = 16),
    command_id BLOB NOT NULL CHECK(length(command_id) = 16),
    idempotency_key BLOB NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    actor BLOB NOT NULL CHECK(length(actor) BETWEEN 1 AND 256),
    payload BLOB NOT NULL,
    integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32),
    correlation_id BLOB NOT NULL CHECK(length(correlation_id) = 16),
    correlation_type INTEGER NOT NULL CHECK(correlation_type IN (1, 2)),
    integrity_profile INTEGER NOT NULL CHECK(integrity_profile IN (1, 2)),
    FOREIGN KEY(aggregate_type, aggregate_id)
        REFERENCES aggregate_streams_v3(aggregate_type, aggregate_id),
    UNIQUE(aggregate_type, aggregate_id, sequence)
);

INSERT INTO events_v3
    (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
     sensitivity, schema_version, causation_id, command_id, idempotency_key,
     actor, payload, integrity_digest, correlation_id, correlation_type,
     integrity_profile)
SELECT event_id, aggregate_type, taskrun_id, sequence, global_position, timestamp,
       sensitivity, schema_version, causation_id, command_id, idempotency_key,
       actor, payload, integrity_digest, correlation_id, correlation_type,
       integrity_profile
FROM events;

DROP TABLE events;
DROP TABLE aggregate_streams;
ALTER TABLE aggregate_streams_v3 RENAME TO aggregate_streams;
ALTER TABLE events_v3 RENAME TO events;

CREATE INDEX idx_events_aggregate_sequence
    ON events(aggregate_type, aggregate_id, sequence);
"#;

// ── Migration V4: migration control plane ───────────────────────────────

const MIGRATION_V4: &str = r#"
CREATE TABLE migration_plans (
    plan_id TEXT PRIMARY KEY CHECK(length(plan_id) BETWEEN 1 AND 128),
    cycle_id TEXT NOT NULL UNIQUE CHECK(length(cycle_id) BETWEEN 1 AND 128),
    cycle_kind INTEGER NOT NULL CHECK(cycle_kind IN (1, 2)),
    parent_cycle_id TEXT CHECK(
        parent_cycle_id IS NULL OR length(parent_cycle_id) BETWEEN 1 AND 128
    ),
    source_generation TEXT NOT NULL CHECK(length(source_generation) BETWEEN 1 AND 128),
    candidate_generation TEXT NOT NULL CHECK(length(candidate_generation) BETWEEN 1 AND 128),
    phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 8),
    status INTEGER NOT NULL CHECK(status IN (1, 2)),
    routing_unit_digest BLOB NOT NULL CHECK(length(routing_unit_digest) = 32),
    gate_policy TEXT NOT NULL CHECK(length(gate_policy) BETWEEN 1 AND 128),
    plan_version INTEGER NOT NULL CHECK(plan_version >= 0),
    created_at INTEGER NOT NULL,
    plan_blob BLOB NOT NULL
);

CREATE TABLE migration_transitions (
    transition_id TEXT PRIMARY KEY CHECK(length(transition_id) BETWEEN 1 AND 128),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    cycle_id TEXT NOT NULL CHECK(length(cycle_id) BETWEEN 1 AND 128),
    from_phase INTEGER NOT NULL CHECK(from_phase BETWEEN 0 AND 8),
    to_phase INTEGER NOT NULL CHECK(to_phase BETWEEN 0 AND 8),
    plan_version INTEGER NOT NULL CHECK(plan_version >= 0),
    occurred_at INTEGER NOT NULL,
    transition_blob BLOB NOT NULL,
    UNIQUE(plan_id, transition_id)
);

CREATE INDEX idx_migration_transitions_plan
    ON migration_transitions(plan_id, plan_version);

CREATE TABLE migration_evidence (
    evidence_digest BLOB PRIMARY KEY CHECK(length(evidence_digest) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    evidence_blob BLOB NOT NULL,
    recorded_at INTEGER NOT NULL,
    UNIQUE(plan_id, evidence_digest)
);

CREATE INDEX idx_migration_evidence_plan
    ON migration_evidence(plan_id);

CREATE TABLE routing_snapshots (
    routing_unit_digest BLOB NOT NULL CHECK(length(routing_unit_digest) = 32),
    routing_generation INTEGER NOT NULL CHECK(routing_generation > 0),
    snapshot_blob BLOB NOT NULL,
    committed_at INTEGER NOT NULL,
    PRIMARY KEY(routing_unit_digest, routing_generation)
);

CREATE TABLE routing_head (
    routing_unit_digest BLOB PRIMARY KEY CHECK(length(routing_unit_digest) = 32),
    routing_generation INTEGER NOT NULL CHECK(routing_generation > 0),
    FOREIGN KEY(routing_unit_digest, routing_generation)
        REFERENCES routing_snapshots(routing_unit_digest, routing_generation)
);

CREATE TABLE runtime_bindings (
    aggregate_type INTEGER NOT NULL CHECK(aggregate_type IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    routing_unit_digest BLOB NOT NULL CHECK(length(routing_unit_digest) = 32),
    routing_generation INTEGER NOT NULL CHECK(routing_generation > 0),
    binding_blob BLOB NOT NULL,
    PRIMARY KEY(aggregate_type, aggregate_id),
    FOREIGN KEY(routing_unit_digest, routing_generation)
        REFERENCES routing_snapshots(routing_unit_digest, routing_generation)
);

CREATE TABLE migration_reports (
    report_id BLOB PRIMARY KEY CHECK(length(report_id) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    report_kind INTEGER NOT NULL CHECK(report_kind BETWEEN 1 AND 255),
    report_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE cutover_manifests (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE rollback_manifests (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    parent_plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE retirement_manifests (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE migration_receipts (
    command_id BLOB PRIMARY KEY CHECK(length(command_id) = 16),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    scope_bytes BLOB NOT NULL CHECK(length(scope_bytes) BETWEEN 1 AND 1024),
    idempotency_key BLOB NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 32),
    outcome_blob BLOB NOT NULL,
    committed_at INTEGER NOT NULL,
    UNIQUE(scope_bytes, idempotency_key)
);

CREATE TABLE migration_audit (
    record_id BLOB PRIMARY KEY CHECK(length(record_id) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    command_id BLOB NOT NULL CHECK(length(command_id) = 16),
    operator_id TEXT NOT NULL CHECK(length(operator_id) BETWEEN 1 AND 128),
    action INTEGER NOT NULL CHECK(action BETWEEN 1 AND 8),
    recorded_at INTEGER NOT NULL,
    record_blob BLOB NOT NULL,
    UNIQUE(plan_id, command_id)
);
"#;

// ── Migration V5: write-ahead routing dispatch intent ──────────────────

const MIGRATION_V5: &str = r#"
CREATE TABLE routing_dispatch_intents (
    aggregate_type INTEGER NOT NULL CHECK(aggregate_type IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    command_id BLOB NOT NULL UNIQUE CHECK(length(command_id) = 16),
    idempotency_key BLOB NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    dispatch_status INTEGER NOT NULL CHECK(dispatch_status BETWEEN 1 AND 4),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(aggregate_type, aggregate_id),
    FOREIGN KEY(aggregate_type, aggregate_id)
        REFERENCES runtime_bindings(aggregate_type, aggregate_id)
);
"#;

// ── Migration V6: immutable artifact cycle lineage ────────────────────

const MIGRATION_V6: &str = r#"
CREATE UNIQUE INDEX idx_migration_plans_plan_cycle
    ON migration_plans(plan_id, cycle_id);

CREATE TABLE migration_reports_v6 (
    report_id BLOB PRIMARY KEY CHECK(length(report_id) = 32),
    plan_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL CHECK(length(cycle_id) BETWEEN 1 AND 128),
    report_kind INTEGER NOT NULL CHECK(report_kind BETWEEN 1 AND 255),
    report_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(plan_id, cycle_id)
        REFERENCES migration_plans(plan_id, cycle_id)
);

INSERT INTO migration_reports_v6
    (report_id, plan_id, cycle_id, report_kind, report_blob, created_at)
SELECT report_id, reports.plan_id, plans.cycle_id, report_kind, report_blob, reports.created_at
FROM migration_reports AS reports
JOIN migration_plans AS plans ON plans.plan_id = reports.plan_id;

CREATE TABLE cutover_manifests_v6 (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL CHECK(length(cycle_id) BETWEEN 1 AND 128),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(plan_id, cycle_id)
        REFERENCES migration_plans(plan_id, cycle_id)
);

INSERT INTO cutover_manifests_v6
    (manifest_id, plan_id, cycle_id, manifest_blob, created_at)
SELECT manifest_id, manifests.plan_id, plans.cycle_id, manifest_blob, manifests.created_at
FROM cutover_manifests AS manifests
JOIN migration_plans AS plans ON plans.plan_id = manifests.plan_id;

CREATE TABLE rollback_manifests_v6 (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL CHECK(length(cycle_id) BETWEEN 1 AND 128),
    parent_plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(plan_id, cycle_id)
        REFERENCES migration_plans(plan_id, cycle_id)
);

INSERT INTO rollback_manifests_v6
    (manifest_id, plan_id, cycle_id, parent_plan_id, manifest_blob, created_at)
SELECT manifest_id, manifests.plan_id, plans.cycle_id, parent_plan_id,
       manifest_blob, manifests.created_at
FROM rollback_manifests AS manifests
JOIN migration_plans AS plans ON plans.plan_id = manifests.plan_id;

CREATE TABLE retirement_manifests_v6 (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL CHECK(length(cycle_id) BETWEEN 1 AND 128),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(plan_id, cycle_id)
        REFERENCES migration_plans(plan_id, cycle_id)
);

INSERT INTO retirement_manifests_v6
    (manifest_id, plan_id, cycle_id, manifest_blob, created_at)
SELECT manifest_id, manifests.plan_id, plans.cycle_id, manifest_blob, manifests.created_at
FROM retirement_manifests AS manifests
JOIN migration_plans AS plans ON plans.plan_id = manifests.plan_id;

DROP TABLE migration_reports;
DROP TABLE cutover_manifests;
DROP TABLE rollback_manifests;
DROP TABLE retirement_manifests;

ALTER TABLE migration_reports_v6 RENAME TO migration_reports;
ALTER TABLE cutover_manifests_v6 RENAME TO cutover_manifests;
ALTER TABLE rollback_manifests_v6 RENAME TO rollback_manifests;
ALTER TABLE retirement_manifests_v6 RENAME TO retirement_manifests;
"#;

// ── Migration V7: atomic security pre-effect transaction ────────────────

const MIGRATION_V7: &str = r#"
CREATE TABLE security_dispatch_intents (
    intent_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status = 'uncertain')
);

CREATE TABLE security_authorization_decisions (
    intent_id TEXT PRIMARY KEY REFERENCES security_dispatch_intents(intent_id),
    grant_id TEXT NOT NULL,
    allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
    reason TEXT NOT NULL
);

CREATE TABLE security_budget_consumptions (
    intent_id TEXT PRIMARY KEY REFERENCES security_dispatch_intents(intent_id),
    reservation_id TEXT NOT NULL,
    amount INTEGER NOT NULL
);

CREATE TABLE security_audit_pre_effect (
    intent_id TEXT PRIMARY KEY REFERENCES security_dispatch_intents(intent_id),
    side_effect_started INTEGER NOT NULL CHECK (side_effect_started = 1)
);

CREATE TABLE security_permit_claims (
    permit_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL UNIQUE REFERENCES security_dispatch_intents(intent_id)
);
"#;

// ── Migration V8: daemon tables + authority ID ─────────────────────────

const MIGRATION_V8: &str = r#"
CREATE TABLE IF NOT EXISTS _authority (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    authority_id BLOB NOT NULL CHECK (length(authority_id) = 16)
);

CREATE TABLE IF NOT EXISTS _daemon_info (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS _replay_subscriptions (
    session_id BLOB PRIMARY KEY CHECK (length(session_id) = 16),
    principal_id TEXT NOT NULL,
    session_generation INTEGER NOT NULL CHECK (session_generation > 0),
    authority_id BLOB NOT NULL CHECK (length(authority_id) = 16),
    authorization_epoch INTEGER NOT NULL CHECK (authorization_epoch >= 0),
    aggregate_type INTEGER NOT NULL,
    aggregate_id BLOB NOT NULL CHECK (length(aggregate_id) = 16),
    retained_floor INTEGER,
    retention_generation INTEGER NOT NULL CHECK (retention_generation = 0),
    high_water_position INTEGER NOT NULL CHECK (high_water_position >= 0),
    next_page_position INTEGER,
    last_delivered_position INTEGER,
    last_acked_position INTEGER,
    state TEXT NOT NULL CHECK (state IN
      ('catching_up','catch_up_complete','activating_live','live','closed')),
    high_water_ref BLOB NOT NULL,
    catch_up_completion BLOB,
    live_delivery_id BLOB,
    created_at TEXT NOT NULL
);
"#;

// ── Migration V9: strict verification tables from released V8 ───────────

const MIGRATION_V9: &str = r#"
CREATE TABLE verification_evidence (
    evidence_id BLOB PRIMARY KEY CHECK(length(evidence_id) = 16),
    run_id BLOB NOT NULL CHECK(length(run_id) = 16),
    profile_id BLOB NOT NULL CHECK(length(profile_id) = 16),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    layer INTEGER NOT NULL CHECK(layer IN (0, 1, 2, 3, 4, 5)),
    evidence_type INTEGER NOT NULL CHECK(evidence_type IN (0, 1, 2, 3, 4)),
    evidence_digest BLOB NOT NULL CHECK(length(evidence_digest) = 32),
    content_ref TEXT NOT NULL CHECK(length(content_ref) > 0),
    source TEXT NOT NULL CHECK(length(source) > 0),
    producer_identity TEXT NOT NULL CHECK(length(producer_identity) > 0),
    sensitivity INTEGER NOT NULL CHECK(sensitivity IN (0, 1, 2)),
    verified_by TEXT NOT NULL CHECK(length(verified_by) > 0)
);

CREATE INDEX IF NOT EXISTS idx_evidence_run
    ON verification_evidence(run_id);

CREATE TABLE consumption_intents (
    intent_id BLOB PRIMARY KEY CHECK(length(intent_id) = 16),
    idempotency_key TEXT NOT NULL UNIQUE CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    state TEXT NOT NULL CHECK(state IN
        ('Reserved','Dispatching','Completed','Failed',
         'Invalidated','Abandoned')),
    gate_head_snapshot_digest BLOB NOT NULL CHECK(length(gate_head_snapshot_digest) = 32),
    target_artifact_digest BLOB NOT NULL CHECK(length(target_artifact_digest) = 32),
    integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32)
);
CREATE TABLE schema_lineage (
    schema_version INTEGER PRIMARY KEY CHECK(schema_version = 9),
    provenance TEXT NOT NULL CHECK(provenance = 'released-v8-to-strict-v9')
);
INSERT INTO schema_lineage (schema_version, provenance)
    VALUES (9, 'released-v8-to-strict-v9');
"#;

/// Open a database connection with the standard set of PRAGMAs.
pub fn open_with_pragmas(db_path: &str) -> SqliteResult<Connection> {
    let is_new_file = db_path != ":memory:" && !Path::new(db_path).exists();
    let conn = Connection::open(db_path)?;

    if is_new_file {
        #[cfg(unix)]
        secure_file_permissions(Path::new(db_path))
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    }

    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;

    // macOS-specific: fullfsync
    #[cfg(target_os = "macos")]
    {
        conn.execute_batch("PRAGMA fullfsync = ON;")?;
    }

    // WAL sidecars are created by the PRAGMA above. Secure them before this
    // newly created database is returned for writable migrations.
    if is_new_file {
        #[cfg(unix)]
        for suffix in ["-wal", "-shm"] {
            let sidecar = std::path::PathBuf::from(format!("{db_path}{suffix}"));
            if sidecar.exists() {
                secure_file_permissions(&sidecar)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            }
        }
    }

    Ok(conn)
}

// ── Authority ID ────────────────────────────────────────────────────────

/// Generate a new random authority ID.
pub fn generate_authority_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

/// Read the authority ID from the database.
/// Returns None if no row exists.
pub fn read_authority_id(conn: &Connection) -> SqliteResult<Option<[u8; 16]>> {
    let mut stmt = conn.prepare("SELECT authority_id FROM _authority WHERE id = 1")?;
    let mut rows = stmt.query([])?;
    match rows.next()? {
        Some(row) => {
            let blob: Vec<u8> = row.get(0)?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&blob);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

/// Insert authority ID (only if no row exists — idempotent).
pub fn ensure_authority_id(conn: &Connection, authority_id: &[u8; 16]) -> SqliteResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO _authority (id, authority_id) VALUES (1, ?1)",
        rusqlite::params![authority_id.as_slice()],
    )?;
    Ok(())
}

// ── Startup purge ───────────────────────────────────────────────────────

/// Purge stale replay subscriptions at startup.
pub fn purge_replay_subscriptions(conn: &Connection) -> SqliteResult<()> {
    conn.execute("DELETE FROM _replay_subscriptions", [])?;
    Ok(())
}

// ── Platform-specific file ACL ──────────────────────────────────────────

/// Platform-specific file ACL (Windows: private DACL, Unix: 0600).
#[cfg(unix)]
pub fn secure_file_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
pub fn secure_file_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    // Windows ACL is handled during file creation in lock.rs
    Ok(())
}

/// Protect parent directory: 0700 (Unix) / private DACL (Windows).
#[cfg(unix)]
pub fn secure_dir_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
pub fn secure_dir_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    const TEST_ID: [u8; 16] = [0x42; 16];

    fn initialize_v1(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .unwrap();
        conn.execute_batch(MIGRATION_V1).unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .unwrap();
    }

    #[test]
    fn migrations_backfill_v1_event_without_changing_durable_identity() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_v1(&conn);
        conn.execute(
            "INSERT INTO task_run_streams
             (taskrun_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (?1, 1, ?1, 0, 0)",
            params![TEST_ID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events
             (event_id, taskrun_id, sequence, global_position, timestamp,
              aggregate_type, sensitivity, schema_version, causation_id,
              command_id, idempotency_key, actor, payload, integrity_digest)
             VALUES (?1, ?1, 1, 1, 0, 1, 0, 1, NULL, ?1, x'01', x'02', x'03', zeroblob(32))",
            params![TEST_ID],
        )
        .unwrap();

        apply_migrations(&conn).unwrap();

        let (
            aggregate_id,
            correlation_id,
            correlation_type,
            integrity_profile,
            global_position,
            integrity_digest,
        ): (Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>) = conn
            .query_row(
                "SELECT aggregate_id, correlation_id, correlation_type, integrity_profile,
                        global_position, integrity_digest
                 FROM events",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(aggregate_id, TEST_ID);
        assert_eq!(correlation_id, TEST_ID);
        assert_eq!(correlation_type, 1);
        assert_eq!(integrity_profile, 1);
        assert_eq!(global_position, 1);
        assert_eq!(integrity_digest, vec![0; 32]);

        let stream_type: i64 = conn
            .query_row(
                "SELECT aggregate_type FROM aggregate_streams WHERE aggregate_id = ?1",
                params![TEST_ID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stream_type, 1);
    }

    #[test]
    fn test_failed_v2_migration_rolls_back_and_can_retry() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_v1(&conn);
        conn.execute_batch("CREATE TABLE aggregate_streams (taskrun_id BLOB PRIMARY KEY)")
            .unwrap();

        assert!(apply_migrations(&conn).is_err());

        let version: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 1);
        let correlation_column_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'correlation_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(correlation_column_count, 0);

        conn.execute_batch("DROP TABLE aggregate_streams").unwrap();
        apply_migrations(&conn).unwrap();

        let version: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'aggregate_streams'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_count, 1);
    }

    #[test]
    fn schema_v6_adds_migration_tables_with_cycle_lineage_atomically() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migrations(&conn).unwrap();

        assert_eq!(CURRENT_SCHEMA_VERSION, 9);
        for table in [
            "migration_plans",
            "migration_transitions",
            "migration_evidence",
            "routing_snapshots",
            "routing_head",
            "runtime_bindings",
            "routing_dispatch_intents",
            "migration_reports",
            "cutover_manifests",
            "rollback_manifests",
            "retirement_manifests",
            "migration_receipts",
            "migration_audit",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "missing migration table {table}");
        }
        for table in [
            "migration_reports",
            "cutover_manifests",
            "rollback_manifests",
            "retirement_manifests",
        ] {
            let cycle_column_count: i64 = conn
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = 'cycle_id'"
                    ),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(cycle_column_count, 1, "missing cycle lineage on {table}");
        }
    }

    #[test]
    fn schema_v7_adds_atomic_pre_effect_tables_together() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migrations(&conn).unwrap();

        for table in [
            "security_dispatch_intents",
            "security_authorization_decisions",
            "security_budget_consumptions",
            "security_audit_pre_effect",
            "security_permit_claims",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "missing atomic pre-effect table {table}");
        }
    }

    #[test]
    fn schema_v6_backfills_existing_artifacts_without_changing_identity_or_bytes() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE migration_plans (
                 plan_id TEXT PRIMARY KEY,
                 cycle_id TEXT NOT NULL UNIQUE
             );
             INSERT INTO migration_plans VALUES ('plan-1', 'cycle-1');
             INSERT INTO migration_plans VALUES ('parent-1', 'parent-cycle-1');
             CREATE TABLE migration_reports (
                 report_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 report_kind INTEGER NOT NULL,
                 report_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE cutover_manifests (
                 manifest_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 manifest_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE rollback_manifests (
                 manifest_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 parent_plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 manifest_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE retirement_manifests (
                 manifest_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 manifest_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             INSERT INTO migration_reports VALUES (zeroblob(32), 'plan-1', 1, x'0102', 10);
             INSERT INTO cutover_manifests VALUES (randomblob(32), 'plan-1', x'0304', 11);
             INSERT INTO rollback_manifests
                 VALUES (randomblob(32), 'plan-1', 'parent-1', x'0506', 12);
             INSERT INTO retirement_manifests VALUES (randomblob(32), 'plan-1', x'0708', 13);",
        )
        .unwrap();

        conn.execute_batch(MIGRATION_V6).unwrap();

        for (table, expected_blob) in [
            ("migration_reports", vec![1_u8, 2]),
            ("cutover_manifests", vec![3_u8, 4]),
            ("rollback_manifests", vec![5_u8, 6]),
            ("retirement_manifests", vec![7_u8, 8]),
        ] {
            let (cycle_id, blob): (String, Vec<u8>) = conn
                .query_row(
                    &format!(
                        "SELECT cycle_id, {}_blob FROM {table}",
                        artifact_blob_prefix(table)
                    ),
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(cycle_id, "cycle-1");
            assert_eq!(blob, expected_blob);
        }
        let mut foreign_key_check = conn.prepare("PRAGMA foreign_key_check").unwrap();
        assert!(!foreign_key_check.exists([]).unwrap());
    }

    fn initialize_released_v8(conn: &Connection) {
        initialize_v1(conn);
        let tx = conn.unchecked_transaction().unwrap();
        tx.execute_batch(MIGRATION_V2).unwrap();
        tx.execute("UPDATE events SET correlation_id = taskrun_id, correlation_type = 1, integrity_profile = 1", []).unwrap();
        tx.execute("INSERT INTO schema_version (version) VALUES (2)", [])
            .unwrap();
        tx.commit().unwrap();
        for (version, migration) in [
            (3, MIGRATION_V3),
            (4, MIGRATION_V4),
            (5, MIGRATION_V5),
            (6, MIGRATION_V6),
            (7, MIGRATION_V7),
            (8, MIGRATION_V8),
        ] {
            let tx = conn.unchecked_transaction().unwrap();
            tx.execute_batch(migration).unwrap();
            tx.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [version],
            )
            .unwrap();
            tx.commit().unwrap();
        }
    }

    #[test]
    fn released_v8_upgrades_atomically_to_strict_v9() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_released_v8(&conn);

        apply_migrations(&conn).unwrap();

        assert_eq!(CURRENT_SCHEMA_VERSION, 9);
        assert_eq!(
            conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            9
        );
        assert!(
            conn.execute(
                "INSERT INTO consumption_intents VALUES (?1, 'key', 'Reserved', ?2, ?2, ?2)",
                params![[1_u8; 15].as_slice(), [2_u8; 32].as_slice()]
            )
            .is_err()
        );
        assert!(conn.execute("INSERT INTO verification_evidence VALUES (?1, ?1, ?1, ?2, 6, 0, ?2, 'blob:test', 'store', 'producer', 0, 'sqlite')", params![[1_u8; 16].as_slice(), [2_u8; 32].as_slice()]).is_err());
    }

    #[test]
    fn candidate_or_future_markers_are_rejected_without_mutation() {
        for marker in [9, 10, 11, 12] {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now'))); CREATE TABLE candidate_data (value TEXT NOT NULL);").unwrap();
            conn.execute("INSERT INTO schema_version (version) VALUES (?1)", [marker])
                .unwrap();
            conn.execute("INSERT INTO candidate_data VALUES ('unchanged')", [])
                .unwrap();
            let before: Vec<(String, String)> = conn
                .prepare("SELECT type, name FROM sqlite_master ORDER BY type, name")
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<SqliteResult<_>>()
                .unwrap();

            assert!(
                apply_migrations(&conn).is_err(),
                "candidate marker V{marker} must fail closed"
            );

            let after: Vec<(String, String)> = conn
                .prepare("SELECT type, name FROM sqlite_master ORDER BY type, name")
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<SqliteResult<_>>()
                .unwrap();
            assert_eq!(after, before);
            assert_eq!(
                conn.query_row("SELECT value FROM candidate_data", [], |row| row
                    .get::<_, String>(0))
                    .unwrap(),
                "unchanged"
            );
        }
    }

    #[test]
    fn tampered_candidate_intent_digest_is_rejected_not_recomputed() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')));
             CREATE TABLE consumption_intents (intent_id BLOB PRIMARY KEY, idempotency_key TEXT NOT NULL, state TEXT NOT NULL, gate_head_snapshot_digest BLOB NOT NULL, target_artifact_digest BLOB NOT NULL, integrity_digest BLOB NOT NULL);",
        )
        .unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (9)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO consumption_intents VALUES (?1, 'legacy', 'Reserved', ?2, ?2, ?3)",
            params![
                [1_u8; 16].as_slice(),
                [2_u8; 32].as_slice(),
                [0xA5_u8; 32].as_slice()
            ],
        )
        .unwrap();

        assert!(apply_migrations(&conn).is_err());

        let digest: Vec<u8> = conn
            .query_row(
                "SELECT integrity_digest FROM consumption_intents",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(digest, vec![0xA5; 32]);
    }

    // Released V8 has no verification tables, so no released legacy intent
    // digest exists to validate or rewrite. Candidate V9+ inputs reject above.

    fn artifact_blob_prefix(table: &str) -> &'static str {
        match table {
            "migration_reports" => "report",
            "cutover_manifests" | "rollback_manifests" | "retirement_manifests" => "manifest",
            _ => unreachable!("test controls the table list"),
        }
    }
}
