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
