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
