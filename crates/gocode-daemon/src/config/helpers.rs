
impl ConfigurationSnapshot {
    /// Build a snapshot from defaults only (no system config file).
    pub fn from_defaults(defaults: &BuiltInDefaults) -> Self {
        let mut provenance = BTreeMap::new();
        provenance.insert("schema_version".into(), builtin_source());
        provenance.insert("db_path".into(), builtin_source());
        provenance.insert("http_bind".into(), builtin_source());
        provenance.insert("replay_integrity_key_path".into(), builtin_source());
        provenance.insert("max_in_flight".into(), builtin_source());
        provenance.insert("shutdown_timeout_ms".into(), builtin_source());

        let provider_activation = ProviderActivation::deterministic_v1();
        let values = canonical_values_map(
            defaults.schema_version,
            &defaults.db_path,
            &defaults.http_bind,
            &defaults.replay_integrity_key_path,
            defaults.max_in_flight,
            defaults.shutdown_timeout_ms,
            provider_activation.binding(),
        );

        Self {
            schema_version: defaults.schema_version,
            db_path: defaults.db_path.clone(),
            http_bind: defaults.http_bind.clone(),
            replay_integrity_key_path: defaults.replay_integrity_key_path.clone(),
            max_in_flight: defaults.max_in_flight,
            shutdown_timeout_ms: defaults.shutdown_timeout_ms,
            provider_activation,
            provenance,
            digest: compute_digest(&values),
        }
    }

    /// Merge defaults with a system config overlay.
    ///
    /// Fields present in `system` override the corresponding defaults;
    /// provenance is updated to `SystemFile` for overridden fields.
    ///
    /// `system_path` is stored in provenance to record where the override
    /// came from.
    pub fn from_merge(
        defaults: &BuiltInDefaults,
        system: &SystemConfig,
        system_path: &Path,
    ) -> Result<Self, DaemonError> {
        let schema_version = defaults.schema_version;
        let db_path = system
            .db_path
            .as_deref()
            .unwrap_or(&defaults.db_path)
            .to_string();
        let http_bind = system
            .http_bind
            .as_deref()
            .unwrap_or(&defaults.http_bind)
            .to_string();
        let replay_integrity_key_path = system
            .replay_integrity_key_path
            .as_deref()
            .unwrap_or(&defaults.replay_integrity_key_path)
            .to_string();
        let max_in_flight = system.max_in_flight.unwrap_or(defaults.max_in_flight);
        let shutdown_timeout_ms = system
            .shutdown_timeout_ms
            .unwrap_or(defaults.shutdown_timeout_ms);

        let provider_activation = system
            .provider_activation
            .as_ref()
            .map(ExternalProviderActivationConfig::binding)
            .transpose()?
            .map(ProviderActivation::from_binding)
            .unwrap_or_else(ProviderActivation::deterministic_v1);
        let mut provenance = BTreeMap::new();
        provenance.insert("schema_version".into(), builtin_source()); // never overridden

        let sys_src = system_source(system_path);

        // db_path
        provenance.insert(
            "db_path".into(),
            select_provenance(system.db_path.is_some(), &sys_src),
        );
        // http_bind
        provenance.insert(
            "http_bind".into(),
            select_provenance(system.http_bind.is_some(), &sys_src),
        );
        // replay_integrity_key_path
        provenance.insert(
            "replay_integrity_key_path".into(),
            select_provenance(system.replay_integrity_key_path.is_some(), &sys_src),
        );
        // max_in_flight
        provenance.insert(
            "max_in_flight".into(),
            select_provenance(system.max_in_flight.is_some(), &sys_src),
        );
        // shutdown_timeout_ms
        provenance.insert(
            "shutdown_timeout_ms".into(),
            select_provenance(system.shutdown_timeout_ms.is_some(), &sys_src),
        );
        provenance.insert(
            "provider_activation".into(),
            select_provenance(system.provider_activation.is_some(), &sys_src),
        );

        let values = canonical_values_map(
            schema_version,
            &db_path,
            &http_bind,
            &replay_integrity_key_path,
            max_in_flight,
            shutdown_timeout_ms,
            provider_activation.binding(),
        );

        Ok(Self {
            schema_version,
            db_path,
            http_bind,
            replay_integrity_key_path,
            max_in_flight,
            shutdown_timeout_ms,
            provider_activation,
            provenance,
            digest: compute_digest(&values),
        })
    }
}

// ── Digest helpers ────────────────────────────────────────────────────

/// Build a `serde_json::Map` with sorted keys for canonical serialization.
fn canonical_values_map(
    schema_version: i64,
    db_path: &str,
    http_bind: &str,
    replay_integrity_key_path: &str,
    max_in_flight: u32,
    shutdown_timeout_ms: u64,
    provider_activation: &ProviderActivationBindingV1,
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
    map.insert(
        "provider_activation".into(),
        serde_json::json!({
            "mode": provider_activation.mode().as_str(),
            "profile_digest": hex::encode(provider_activation.profile_digest()),
            "profile_id": provider_activation.profile_id(),
        }),
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

// ── Public API ────────────────────────────────────────────────────────

/// Load configuration.
///
/// If `system_config_path` is `Some`, it is an explicit owner-private file and
/// is parsed from the verified open handle. A missing explicit path is an error.
/// TOML and merged over `BuiltInDefaults`.  Schema version must be `2`;
/// unknown keys, duplicate keys, and type mismatches are rejected.
///
/// If the path is `None`, a snapshot built purely from defaults is returned.
///
/// If the file exists but is malformed or invalid, an error is returned
/// and no partial snapshot is published.
pub fn load_config(
    system_config_path: Option<&Path>,
) -> Result<ConfigurationSnapshot, DaemonError> {
    let runtime_dir = resolve_runtime_dir();
    let defaults = BuiltInDefaults::new(&runtime_dir);

    match system_config_path {
        Some(path) => {
            let contents = read_explicit_config(path)?;
            let system: SystemConfig = toml::from_str(&contents)?;

            // Schema version gate
            if system.schema_version != 2 {
                return Err(DaemonError::Schema(format!(
                    "unsupported schema_version: expected 2, got {}",
                    system.schema_version
                )));
            }

            ConfigurationSnapshot::from_merge(&defaults, &system, path)
        }
        _ => Ok(ConfigurationSnapshot::from_defaults(&defaults)),
    }
}
