const MIGRATION_V10: &str = r#"
CREATE TABLE provider_prepared_requests (
    call_id BLOB PRIMARY KEY CHECK(length(call_id) = 16),
    prepared_digest BLOB NOT NULL CHECK(length(prepared_digest) = 32),
    render_digest BLOB NOT NULL CHECK(length(render_digest) = 32),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32)
);

CREATE TABLE provider_dispatch_attempts (
    attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id) = 16),
    call_id BLOB NOT NULL UNIQUE REFERENCES provider_prepared_requests(call_id),
    permit_id BLOB NOT NULL UNIQUE CHECK(length(permit_id) = 16),
    token_reservation_id BLOB NOT NULL CHECK(length(token_reservation_id) = 16),
    cost_reservation_id BLOB NOT NULL CHECK(length(cost_reservation_id) = 16),
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    provider_idempotency_key TEXT NOT NULL UNIQUE
        CHECK(length(provider_idempotency_key) BETWEEN 1 AND 256),
    prepared_digest BLOB NOT NULL CHECK(length(prepared_digest) = 32),
    render_digest BLOB NOT NULL CHECK(length(render_digest) = 32),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    state INTEGER NOT NULL CHECK(state IN (1, 2, 3, 4)),
    stream_id BLOB CHECK(stream_id IS NULL OR length(stream_id) = 16),
    settlement_digest BLOB CHECK(
        settlement_digest IS NULL OR length(settlement_digest) = 32
    )
);
"#;

// ── Migration V11: provider effect authority admission ──────────────────

const MIGRATION_V11: &str = r#"
CREATE TABLE provider_effect_authorities (
    authority_id BLOB NOT NULL CHECK(length(authority_id) = 16 AND authority_id != zeroblob(16)),
    revision INTEGER NOT NULL CHECK(revision > 0),
    attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
    permit_id BLOB NOT NULL CHECK(length(permit_id) = 16),
    capability_grant_id TEXT NOT NULL CHECK(length(capability_grant_id) BETWEEN 1 AND 256),
    token_reservation_id BLOB NOT NULL CHECK(length(token_reservation_id) = 16),
    cost_reservation_id BLOB NOT NULL CHECK(length(cost_reservation_id) = 16),
    prepared_digest BLOB NOT NULL CHECK(length(prepared_digest) = 32),
    render_digest BLOB NOT NULL CHECK(length(render_digest) = 32),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    owner_id TEXT NOT NULL CHECK(length(owner_id) BETWEEN 1 AND 256),
    scope TEXT NOT NULL CHECK(length(scope) BETWEEN 1 AND 256),
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
    consumed INTEGER NOT NULL CHECK(consumed IN (0, 1)),
    consumed_intent_id TEXT UNIQUE,
    PRIMARY KEY(authority_id, revision),
    CHECK((consumed = 0 AND consumed_intent_id IS NULL) OR
          (consumed = 1 AND consumed_intent_id IS NOT NULL))
);
"#;
