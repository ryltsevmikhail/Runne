const MIGRATION_V12: &str = r#"
ALTER TABLE provider_prepared_requests ADD COLUMN call_digest_version INTEGER NOT NULL DEFAULT 1
    CHECK(call_digest_version IN (1, 2));
ALTER TABLE provider_dispatch_attempts RENAME TO provider_dispatch_attempts_v10;
CREATE TABLE provider_dispatch_attempts (
    attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id) = 16),
    call_id BLOB NOT NULL UNIQUE REFERENCES provider_prepared_requests(call_id),
    permit_id BLOB NOT NULL UNIQUE CHECK(length(permit_id) = 16),
    token_reservation_id BLOB NOT NULL CHECK(length(token_reservation_id) = 16),
    cost_reservation_id BLOB NOT NULL CHECK(length(cost_reservation_id) = 16),
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    provider_idempotency_key TEXT NOT NULL UNIQUE CHECK(length(provider_idempotency_key) BETWEEN 1 AND 256),
    prepared_digest BLOB NOT NULL CHECK(length(prepared_digest) = 32),
    render_digest BLOB NOT NULL CHECK(length(render_digest) = 32),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    state INTEGER NOT NULL CHECK(state IN (1, 2, 3, 4, 5, 6)),
    stream_id BLOB CHECK(stream_id IS NULL OR length(stream_id) = 16),
    settlement_digest BLOB CHECK(settlement_digest IS NULL OR length(settlement_digest) = 32),
    pre_effect_rejection INTEGER CHECK(pre_effect_rejection IS NULL OR pre_effect_rejection IN (1, 2, 3, 4, 5, 6, 7)),
    CHECK((state = 2 AND pre_effect_rejection IS NOT NULL) OR (state != 2 AND pre_effect_rejection IS NULL)),
    CHECK((state IN (3, 4) AND stream_id IS NOT NULL) OR (state IN (1, 2) AND stream_id IS NULL) OR state IN (5, 6)),
    CHECK((state IN (4, 5) AND settlement_digest IS NOT NULL) OR (state IN (1, 2, 3) AND settlement_digest IS NULL) OR state = 6)
);
INSERT INTO provider_dispatch_attempts (attempt_id, call_id, permit_id, token_reservation_id, cost_reservation_id, fencing_token, provider_idempotency_key, prepared_digest, render_digest, profile_digest, state, stream_id, settlement_digest, pre_effect_rejection)
SELECT attempt_id, call_id, permit_id, token_reservation_id, cost_reservation_id, fencing_token, provider_idempotency_key, prepared_digest, render_digest, profile_digest,
    CASE state WHEN 1 THEN 1 WHEN 2 THEN 3 WHEN 3 THEN 5 WHEN 4 THEN 6 END, stream_id, settlement_digest, NULL
FROM provider_dispatch_attempts_v10;
DROP TABLE provider_dispatch_attempts_v10;
CREATE TABLE schema_upgrade_fence (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    source_version INTEGER NOT NULL CHECK(source_version = 11),
    target_version INTEGER NOT NULL CHECK(target_version = 12),
    snapshot_filename TEXT, snapshot_digest BLOB,
    baseline_event_next_position INTEGER NOT NULL CHECK(baseline_event_next_position > 0),
    baseline_provider_prepared_count INTEGER NOT NULL CHECK(baseline_provider_prepared_count >= 0),
    baseline_provider_attempt_count INTEGER NOT NULL CHECK(baseline_provider_attempt_count >= 0),
    CHECK((snapshot_filename IS NULL AND snapshot_digest IS NULL) OR (length(snapshot_filename) BETWEEN 1 AND 255 AND instr(snapshot_filename, '/') = 0 AND instr(snapshot_filename, char(92)) = 0 AND length(snapshot_digest) = 32))
);
CREATE TABLE schema_upgrade_write_latch (
    id INTEGER PRIMARY KEY CHECK(id = 1), closed INTEGER NOT NULL CHECK(closed = 1)
);
"#;
