pub const TABLES: [&str; 9] = [
    "drafts",
    "event_journal",
    "meta",
    "mutation_ledger",
    "projections",
    "recent_roots",
    "replay_cursors",
    "settings",
    "window_layout",
];

pub const V4_TABLES: [&str; 9] = [
    "drafts",
    "event_journal",
    "meta",
    "mutation_ledger",
    "projections",
    "projects",
    "replay_cursors",
    "settings",
    "window_layout",
];

pub fn expected_columns(table: &str) -> Option<&'static [&'static str]> {
    match table {
        "drafts" => Some(&[
            "runtime_authority",
            "principal",
            "project_id",
            "run_id",
            "body",
            "revision",
            "updated_at",
        ]),
        "event_journal" => Some(&[
            "runtime_authority",
            "principal",
            "lineage",
            "scope",
            "binding_digest",
            "event_id",
            "cursor",
            "generation",
            "event_sequence",
            "validated_event",
            "event_digest",
            "projection_revision",
            "projection_digest",
            "projected_payload",
        ]),
        "meta" => Some(&[
            "singleton",
            "schema_version",
            "db_generation",
            "last_transaction_digest",
            "commit_marker",
        ]),
        "mutation_ledger" => Some(&[
            "runtime_authority",
            "principal",
            "operation_id",
            "idempotency_key",
            "target",
            "disposition",
        ]),
        "projections" => Some(&[
            "runtime_authority",
            "principal",
            "lineage",
            "scope",
            "binding_digest",
            "projection_revision",
            "projection_digest",
            "event_sequence",
            "payload",
        ]),
        "recent_roots" => Some(&[
            "project_id",
            "workspace_id",
            "display_name",
            "last_opened_at",
            "root_state",
            "native_root_metadata",
            "legacy_project_id",
        ]),
        "replay_cursors" => Some(&[
            "runtime_authority",
            "principal",
            "lineage",
            "scope",
            "binding_digest",
            "generation",
            "applied_cursor",
            "event_sequence",
            "projection_revision",
            "projection_digest",
        ]),
        "settings" => Some(&["key", "value", "revision"]),
        "window_layout" => Some(&["profile", "display_topology", "geometry", "revision"]),
        _ => None,
    }
}

pub fn expected_index_count(table: &str) -> i64 {
    match table {
        "recent_roots" | "event_journal" => 3,
        "mutation_ledger" => 2,
        "settings" | "drafts" | "projections" | "replay_cursors" | "window_layout" => 1,
        _ => 0,
    }
}

pub fn expected_sql_hash(schema_version: i64, table: &str) -> Option<&'static str> {
    match (schema_version, table) {
        (4, "projects") => Some("64107989ea7316017666123d192563a7c8e30553b512bc6c8726151303d5351a"),
        (4 | 5, "drafts") => {
            Some("db6ae52e90bbd4322970a6902a032feee351dba39c0968d97b4481320743c0ee")
        }
        (4 | 5, "event_journal") => {
            Some("174ceb2e6d8f7dc715f8ddf3cec67416567d5bb7343eb4e06dfaa722ac9f9fbd")
        }
        (4 | 5, "meta") => Some("759725f52ddfc9edcde3af2a350e36db5b6619a684ac0a3bda3e6fe1021d0fb4"),
        (4 | 5, "mutation_ledger") => {
            Some("f3d2de57f9204b49a3a9527a4c6a543e4b1fb9ae12c1d83301a750966bb2b35e")
        }
        (4 | 5, "projections") => {
            Some("1ea3ba2c6de9ef42508353790d17ecfbaf430da2eb189d2561ca5020d37248fc")
        }
        (5, "recent_roots") => {
            Some("a17614fef2aada43f32e7f330c457dcd711de74b805a9ddee397a9c1ec8b2fa2")
        }
        (4 | 5, "replay_cursors") => {
            Some("3eb39a4fbc5f2f569bcc66e848121fa29960c9cf7f6dc87866fc6fb3cb8980c3")
        }
        (4 | 5, "settings") => {
            Some("c2a7d25293d344e17ff66b50536ad28527e0c999c12731de39a77b8ed552f6be")
        }
        (4 | 5, "window_layout") => {
            Some("389192bd49d507183e98e2c30fb24dc6fe67f3793911dde42654d63d51a1be21")
        }
        _ => None,
    }
}
