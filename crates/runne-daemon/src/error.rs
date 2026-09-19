//! Daemon error types.
//!
//! Central error enum for all daemon subsystems.
//! Every variant carries a human-readable message.

use std::fmt;

use runne_store::schema::SchemaOpenDiagnostic;
use runne_store::schema::recovery_diagnosis::StoreRecoveryDiagnosis;

/// Stage where the runtime store connection was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStoreOpenStage {
    /// Admission/reopen of the connection itself failed.
    Open,
    /// The post-open readiness/publication verification failed.
    Verify,
}

/// Closed classification of the ORIGINAL rejection cause of a runtime store
/// open/verify failure — not the file-health diagnosis. Closed enums only:
/// no raw error text, no paths (DP1 section 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeStoreRejection {
    /// Authority/lineage validation rejected the connection. The file may be
    /// perfectly healthy — `recovery_state` may be `Ready`; the rejection is
    /// admission-side, not file health.
    IdentityMismatch,
    /// The store layer's typed admission diagnostic (zero-byte database,
    /// sidecar present, file identity uncertain, unsafe path).
    Admission(SchemaOpenDiagnostic),
    /// No typed payload exists for this failure in the current store contract
    /// (e.g. startup-gate failures raise `rusqlite::Error::InvalidQuery`).
    /// Fail closed; the paired `recovery_state` still carries typed file
    /// detail.
    Unavailable,
}

/// Structured cause of a runtime store open/verify rejection at the daemon
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStoreOpenRejection {
    /// Static literal from the call site, e.g. "runtime writer".
    pub purpose: String,
    /// Stage that rejected the connection.
    pub stage: RuntimeStoreOpenStage,
    /// Closed classification of the original rejection cause.
    pub rejection: RuntimeStoreRejection,
    /// Supplementary typed file-recovery state; never substitutes
    /// [`Self::rejection`].
    pub recovery_state: StoreRecoveryDiagnosis,
}

/// Unified error type for the runne-daemon process.
#[derive(Debug)]
pub enum DaemonError {
    /// Configuration loading or validation failure.
    Config(String),
    /// Filesystem I/O error.
    Io(std::io::Error),
    /// Instance lock failure (another daemon may be running).
    Lock(String),
    /// Bootstrap / health-check failure.
    Bootstrap(String),
    /// Schema mismatch or validation error.
    Schema(String),
    /// Runtime store open/verify rejected. Carries the structured typed cause
    /// to the daemon boundary (DP1 section 7): `rejection` classifies the
    /// ORIGINAL failure, while `recovery_state` is supplementary typed file
    /// detail and never replaces the rejection. Display prints closed enums
    /// only — no raw store error text, no database path.
    StoreOpenRejection(RuntimeStoreOpenRejection),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "config error: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Lock(msg) => write!(f, "lock error: {msg}"),
            Self::Bootstrap(msg) => write!(f, "bootstrap error: {msg}"),
            Self::Schema(msg) => write!(f, "schema error: {msg}"),
            Self::StoreOpenRejection(rejection) => write!(
                f,
                "store {} {:?} rejected: {:?}; recovery state: {:?}",
                rejection.purpose, rejection.stage, rejection.rejection, rejection.recovery_state
            ),
        }
    }
}

impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DaemonError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<toml::de::Error> for DaemonError {
    fn from(err: toml::de::Error) -> Self {
        Self::Config(err.to_string())
    }
}

impl From<runne_http::secure_local_host::LocalRuntimeTlsHostError> for DaemonError {
    fn from(_: runne_http::secure_local_host::LocalRuntimeTlsHostError) -> Self {
        Self::Bootstrap("local runtime TLS host unavailable".to_owned())
    }
}
