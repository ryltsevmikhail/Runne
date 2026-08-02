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

// ── Migration V10: provider prepare/dispatch durability ─────────────────
