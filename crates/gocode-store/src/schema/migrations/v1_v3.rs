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
