// ── Digest helpers ────────────────────────────────────────────────────

/// Build a `serde_json::Map` with sorted keys for canonical serialization.
fn canonical_values_map(
    schema_version: i64,
    db_path: &str,
    http_bind: &str,
    replay_integrity_key_path: &str,
    max_in_flight: u32,
    shutdown_timeout_ms: u64,
) -> serde_json::Map<String, serde_json::Value> {
    // Insert keys in alphabetical order — serde_json::Map is BTreeMap-backed,
    // so iteration order matches insertion order, giving us canonical output.
    let mut map = serde_json::Map::new();
    map.insert("db_path".into(), serde_json::Value::String(db_path.into()));
    map.insert(
        "http_bind".into(),
        serde_json::Value::String(http_bind.into()),
    );
    map.insert(
        "max_in_flight".into(),
        serde_json::Value::Number((max_in_flight).into()),
    );
    map.insert(
        "schema_version".into(),
        serde_json::Value::Number((schema_version).into()),
    );
    map.insert(
        "shutdown_timeout_ms".into(),
        serde_json::Value::Number((shutdown_timeout_ms).into()),
    );
    map.insert(
        "replay_integrity_key_path".into(),
        serde_json::Value::String(replay_integrity_key_path.into()),
    );
    map
}

/// Compute SHA-256 hex digest of canonical JSON (no whitespace, sorted keys).
fn compute_digest(values: &serde_json::Map<String, serde_json::Value>) -> String {
    let json = serde_json::to_string(values).expect("canonical JSON serialization is infallible");
    let hash = Sha256::digest(json.as_bytes());
    hex::encode(hash)
}

// ── Provenance helpers ────────────────────────────────────────────────

/// Return `sys` if the field was overridden, otherwise a built-in source.
fn select_provenance(overridden: bool, sys: &FieldSource) -> FieldSource {
    if overridden {
        sys.clone()
    } else {
        builtin_source()
    }
}
