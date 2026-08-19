// Daemon configuration subsystem.
//
// Implements ADR-0014 bootstrap subset:
// - `BuiltInDefaults` — mandatory defaults.
// - `SystemConfig` — optional TOML overrides on top of defaults.
// - `ConfigurationSnapshot` — immutable merge result with provenance and
//   deterministic digest (SHA-256 of canonical JSON).

use crate::error::DaemonError;
use crate::provider_activation::ProviderActivation;
use runne_api::{ProviderActivationBindingV1, ProviderActivationModeV1};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::io::Read as _;
use std::path::{Path, PathBuf};

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

#[cfg(unix)]
const MAX_EXTERNAL_CONFIG_BYTES: u64 = 16 * 1024;

/// Fixed native owner-scoped source for external daemon selection.
#[must_use]
pub fn external_config_path() -> PathBuf {
    dirs::config_local_dir()
        .or_else(dirs::config_dir)
        .unwrap_or_else(resolve_runtime_dir)
        .join("runne-daemon")
        .join("config.toml")
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
        let base = runtime_dir.join("runne-daemon");
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
    pub provider_activation: Option<ExternalProviderActivationConfig>,
}

/// Explicit owner-controlled, non-secret external provider selection.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalProviderActivationConfig {
    mode: String,
    profile_id: String,
    profile_digest: String,
}

impl ExternalProviderActivationConfig {
    fn binding(&self) -> Result<ProviderActivationBindingV1, DaemonError> {
        let mode = ProviderActivationModeV1::try_from(self.mode.as_str())
            .map_err(|_| DaemonError::Config("invalid provider activation mode".into()))?;
        let digest = hex::decode(&self.profile_digest)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| DaemonError::Config("invalid provider activation digest".into()))?;
        ProviderActivationBindingV1::new(mode, self.profile_id.clone(), digest)
            .map_err(|_| DaemonError::Config("invalid provider activation profile".into()))
    }
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
    /// Exact non-secret provider selection; defaulting is deterministic only.
    pub provider_activation: ProviderActivation,

    /// Per-field provenance map (field name → source).
    pub provenance: BTreeMap<String, FieldSource>,

    /// SHA-256 hex digest of the canonical JSON representation of
    /// **all** configuration values (alphabetical keys, no whitespace).
    pub digest: String,
}
