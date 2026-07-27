//! Daemon error types.
//!
//! Central error enum for all daemon subsystems.
//! Every variant carries a human-readable message.

use std::fmt;

/// Unified error type for the gocode-daemon process.
#[derive(Debug)]
pub enum DaemonError {
    /// Configuration loading or validation failure.
    Config(String),
    /// Filesystem I/O error.
    Io(std::io::Error),
    /// Token acquisition or renewal failure.
    Token(String),
    /// Instance lock failure (another daemon may be running).
    Lock(String),
    /// Bootstrap / health-check failure.
    Bootstrap(String),
    /// Schema mismatch or validation error.
    Schema(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "config error: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Token(msg) => write!(f, "token error: {msg}"),
            Self::Lock(msg) => write!(f, "lock error: {msg}"),
            Self::Bootstrap(msg) => write!(f, "bootstrap error: {msg}"),
            Self::Schema(msg) => write!(f, "schema error: {msg}"),
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
