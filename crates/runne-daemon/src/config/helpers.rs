#[path = "helpers/canonical_values.rs"]
mod canonical_values;
use canonical_values::{canonical_values_map, compute_digest};

impl ConfigurationSnapshot {
    /// Copy only the D2 finite-budget opt-in from a verified external snapshot.
    /// Protected startup uses this without importing external DB/provider settings.
    #[cfg(feature = "desktop-protected")]
    pub(crate) fn with_d2_tool_budget_from(&self, external: &Self) -> Self {
        let mut snapshot = self.clone();
        snapshot.d2_safe_tool_loop_budget = external.d2_safe_tool_loop_budget;
        if snapshot.d2_safe_tool_loop_budget.is_some()
            && let Some(source) = external.provenance.get("d2_safe_tool_loop_budget")
        {
            snapshot
                .provenance
                .insert("d2_safe_tool_loop_budget".into(), source.clone());
        }
        let mut values = canonical_values_map(
            snapshot.schema_version,
            &snapshot.db_path,
            &snapshot.http_bind,
            &snapshot.replay_integrity_key_path,
            snapshot.max_in_flight,
            snapshot.shutdown_timeout_ms,
            snapshot.provider_activation.binding(),
            Some(&snapshot.provider_activation_settings),
            snapshot.d2_safe_tool_loop_budget,
        );
        if let Some(host) = &snapshot.linux_cli_credential_host {
            values.insert("linux_cli_credential_host".into(), serde_json::json!(host));
        }
        snapshot.digest = compute_digest(&values);
        snapshot
    }

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
        let provider_settings = ProviderActivationSettings::default();
        let values = canonical_values_map(
            defaults.schema_version,
            &defaults.db_path,
            &defaults.http_bind,
            &defaults.replay_integrity_key_path,
            defaults.max_in_flight,
            defaults.shutdown_timeout_ms,
            provider_activation.binding(),
            Some(&provider_settings),
            None,
        );

        Self {
            schema_version: defaults.schema_version,
            db_path: defaults.db_path.clone(),
            http_bind: defaults.http_bind.clone(),
            replay_integrity_key_path: defaults.replay_integrity_key_path.clone(),
            max_in_flight: defaults.max_in_flight,
            shutdown_timeout_ms: defaults.shutdown_timeout_ms,
            provider_activation,
            provider_activation_settings: provider_settings,
            linux_cli_credential_host: None,
            secondary_profile_catalog: None,
            d2_safe_tool_loop_budget: None,
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
        if system
            .d2_safe_tool_loop_budget
            .is_some_and(|budget| budget.limits().is_none())
        {
            return Err(DaemonError::Config("invalid D2 tool-loop budget".into()));
        }
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

        let (provider_binding, provider_settings) = system
            .provider_activation
            .as_ref()
            .map(ExternalProviderActivationConfig::binding_and_settings)
            .transpose()?
            .unwrap_or_else(|| {
                (
                    ProviderActivation::deterministic_v1().binding().clone(),
                    Default::default(),
                )
            });
        let provider_activation = ProviderActivation::from_binding_with_settings(
            provider_binding,
            provider_settings.clone(),
        );
        let mut provenance = BTreeMap::new();
        provenance.insert("schema_version".into(), builtin_source()); // never overridden

        let sys_src = system_source(system_path);

        provenance.insert(
            "linux_cli_credential_host".into(),
            select_provenance(system.linux_cli_credential_host.is_some(), &sys_src),
        );
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
        provenance.insert(
            "secondary_profile_catalog".into(),
            select_provenance(system.secondary_profile_catalog.is_some(), &sys_src),
        );
        provenance.insert(
            "d2_safe_tool_loop_budget".into(),
            select_provenance(system.d2_safe_tool_loop_budget.is_some(), &sys_src),
        );

        let mut values = canonical_values_map(
            schema_version,
            &db_path,
            &http_bind,
            &replay_integrity_key_path,
            max_in_flight,
            shutdown_timeout_ms,
            provider_activation.binding(),
            Some(&provider_settings),
            system.d2_safe_tool_loop_budget,
        );
        if let Some(host) = &system.linux_cli_credential_host {
            host.validate(provider_activation.binding().mode())?;
            values.insert(
                "linux_cli_credential_host".into(),
                serde_json::to_value(host)
                    .map_err(|_| DaemonError::Config("invalid CLI credential host".into()))?,
            );
        }

        Ok(Self {
            schema_version,
            db_path,
            http_bind,
            replay_integrity_key_path,
            max_in_flight,
            shutdown_timeout_ms,
            provider_activation,
            provider_activation_settings: provider_settings,
            linux_cli_credential_host: system.linux_cli_credential_host.clone(),
            secondary_profile_catalog: system.secondary_profile_catalog.clone(),
            d2_safe_tool_loop_budget: system.d2_safe_tool_loop_budget,
            provenance,
            digest: compute_digest(&values),
        })
    }
}

// ── Digest helpers ────────────────────────────────────────────────────

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

#[path = "helpers/installation_upgrade.rs"]
mod installation_upgrade;
