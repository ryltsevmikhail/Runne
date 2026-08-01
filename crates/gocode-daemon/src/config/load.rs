// ── Public API ────────────────────────────────────────────────────────

/// Load configuration.
///
/// If `system_config_path` is `Some` and the file exists, it is parsed as
/// TOML and merged over `BuiltInDefaults`.  Schema version must be `2`;
/// unknown keys, duplicate keys, and type mismatches are rejected.
///
/// If the path is `None` or the file does not exist, a snapshot built
/// purely from defaults is returned (this is *not* an error).
///
/// If the file exists but is malformed or invalid, an error is returned
/// and no partial snapshot is published.
pub fn load_config(
    system_config_path: Option<&Path>,
) -> Result<ConfigurationSnapshot, DaemonError> {
    let runtime_dir = resolve_runtime_dir();
    let defaults = BuiltInDefaults::new(&runtime_dir);

    match system_config_path {
        Some(path) if path.exists() => {
            let contents = fs::read_to_string(path)?;
            let system: SystemConfig = toml::from_str(&contents)?;

            // Schema version gate
            if system.schema_version != 2 {
                return Err(DaemonError::Schema(format!(
                    "unsupported schema_version: expected 2, got {}",
                    system.schema_version
                )));
            }

            Ok(ConfigurationSnapshot::from_merge(&defaults, &system, path))
        }
        _ => Ok(ConfigurationSnapshot::from_defaults(&defaults)),
    }
}
