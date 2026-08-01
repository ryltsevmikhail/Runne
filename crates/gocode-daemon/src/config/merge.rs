// ── Resolution helpers ───────────────────────────────────────────────

/// Resolve the OS runtime directory used for all daemon data.
///
/// Priority:
/// 1. `$XDG_RUNTIME_DIR` or equivalent via `dirs::runtime_dir()`
/// 2. `$XDG_DATA_HOME` or equivalent via `dirs::data_local_dir()`
/// 3. `$HOME/.local/share` (or `%LOCALAPPDATA%` on Windows)
fn resolve_runtime_dir() -> PathBuf {
    dirs::runtime_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| {
            let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            home.join(".local").join("share")
        })
}

// ── Provenance ────────────────────────────────────────────────────────

/// Describes where a configuration value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSource {
    /// Origin of the value.
    pub source: Source,
    /// Filesystem path for `SystemFile` sources; `None` for `BuiltIn`.
    pub path: Option<String>,
}

/// Origin of a configuration field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Value came from built-in defaults.
    BuiltIn,
    /// Value came from the system configuration file.
    SystemFile,
}

/// Convenience constructor for built-in provenance.
fn builtin_source() -> FieldSource {
    FieldSource {
        source: Source::BuiltIn,
        path: None,
    }
}

/// Convenience constructor for system-file provenance.
fn system_source(path: &Path) -> FieldSource {
    FieldSource {
        source: Source::SystemFile,
        path: Some(path.display().to_string()),
    }
}

// ── BuiltInDefaults ───────────────────────────────────────────────────

/// Mandatory built-in defaults (ADR-0014 bootstrap subset).
///
/// All path fields are **resolved** — `{OS_RUNTIME_DIR}` is already
/// replaced with the concrete runtime directory.
#[derive(Debug, Clone)]
pub struct BuiltInDefaults {
    /// Schema version (always 2).
    pub schema_version: i64,
    /// Path to the event-log SQLite database.
    pub db_path: String,
    /// HTTP bind address.
    pub http_bind: String,
    /// Path to the internal replay-integrity key.
    pub replay_integrity_key_path: String,
    /// Maximum concurrent in-flight operations.
    pub max_in_flight: u32,
    /// Graceful-shutdown timeout in milliseconds.
    pub shutdown_timeout_ms: u64,
}

impl BuiltInDefaults {
    /// Create defaults with paths rooted at the OS runtime directory.
    pub fn new(runtime_dir: &Path) -> Self {
        let base = runtime_dir.join("gocode-daemon");
        Self {
            schema_version: 2,
            db_path: base.join("event-log.db").display().to_string(),
            http_bind: "127.0.0.1:3000".to_string(),
            replay_integrity_key_path: base.join("replay-integrity.key").display().to_string(),
            max_in_flight: 100,
            shutdown_timeout_ms: 10_000,
        }
    }
}

// ── SystemConfig (TOML overlay) ───────────────────────────────────────

/// Optional TOML configuration overlay.
///
/// Every field is optional — only present keys override the corresponding
/// built-in default.  Unknown keys are rejected at parse time.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemConfig {
    /// Must be exactly `2`; any other value is a schema error.
    pub schema_version: i64,
    pub db_path: Option<String>,
    pub http_bind: Option<String>,
    pub replay_integrity_key_path: Option<String>,
    pub max_in_flight: Option<u32>,
    pub shutdown_timeout_ms: Option<u64>,
}

// ── ConfigurationSnapshot ─────────────────────────────────────────────

/// Immutable configuration snapshot.
///
/// Built by merging `BuiltInDefaults` with an optional `SystemConfig`.
/// Every field carries provenance so consumers can tell whether a value
/// is a default or a user override.
#[derive(Debug, Clone)]
pub struct ConfigurationSnapshot {
    // ── resolved values ──
    pub schema_version: i64,
    pub db_path: String,
    pub http_bind: String,
    pub replay_integrity_key_path: String,
    pub max_in_flight: u32,
    pub shutdown_timeout_ms: u64,

    /// Per-field provenance map (field name → source).
    pub provenance: BTreeMap<String, FieldSource>,

    /// SHA-256 hex digest of the canonical JSON representation of
    /// **all** configuration values (alphabetical keys, no whitespace).
    pub digest: String,
}

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

        let values = canonical_values_map(
            defaults.schema_version,
            &defaults.db_path,
            &defaults.http_bind,
            &defaults.replay_integrity_key_path,
            defaults.max_in_flight,
            defaults.shutdown_timeout_ms,
        );

        Self {
            schema_version: defaults.schema_version,
            db_path: defaults.db_path.clone(),
            http_bind: defaults.http_bind.clone(),
            replay_integrity_key_path: defaults.replay_integrity_key_path.clone(),
            max_in_flight: defaults.max_in_flight,
            shutdown_timeout_ms: defaults.shutdown_timeout_ms,
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
    ) -> Self {
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

        let values = canonical_values_map(
            schema_version,
            &db_path,
            &http_bind,
            &replay_integrity_key_path,
            max_in_flight,
            shutdown_timeout_ms,
        );

        Self {
            schema_version,
            db_path,
            http_bind,
            replay_integrity_key_path,
            max_in_flight,
            shutdown_timeout_ms,
            provenance,
            digest: compute_digest(&values),
        }
    }
}
