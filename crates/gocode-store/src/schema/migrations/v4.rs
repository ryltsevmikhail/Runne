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
