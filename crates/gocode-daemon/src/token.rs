//! Daemon token lifecycle management.
//!
//! Implements ADR-0014 token provisioning:
//! - provision: create a 32-byte random token file with 0600 permissions
//! - load: read exactly 32 bytes from the token file
//! - verify: constant-time comparison via `subtle::ConstantTimeEq`

use crate::error::DaemonError;
use rand::RngCore;
use rand::rngs::OsRng;
use std::fs;
use std::io::Write;
use std::path::Path;
use subtle::ConstantTimeEq;

/// A 32-byte daemon authentication token.
#[derive(Clone, PartialEq, Eq)]
pub struct DaemonToken(pub [u8; 32]);

impl std::fmt::Debug for DaemonToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DaemonToken")
            .field(&format_args!("<redacted>"))
            .finish()
    }
}

/// Stateless manager for daemon token lifecycle operations.
pub struct TokenManager;

impl TokenManager {
    /// Create a new token file at `path`.
    ///
    /// Generates 32 random bytes via `OsRng`, writes them to a new file
    /// (exclusive `File::create_new`) with `0o600` permissions, and
    /// calls `sync_all`.  Parent directories are created if needed.
    ///
    /// Returns `DaemonError::Token` if the file already exists.
    pub fn provision(path: &Path) -> Result<DaemonToken, DaemonError> {
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                DaemonError::Token(format!("failed to create parent directory for token: {e}"))
            })?;
        }

        let file = fs::File::create_new(path).map_err(|e| {
            DaemonError::Token(format!(
                "failed to create token file at {path}: {e}",
                path = path.display()
            ))
        })?;

        // Set permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    DaemonError::Token(format!("failed to set token file permissions: {e}"))
                })?;
        }

        let mut file = file;
        file.write_all(&token)
            .map_err(|e| DaemonError::Token(format!("failed to write token: {e}")))?;
        file.sync_all()
            .map_err(|e| DaemonError::Token(format!("failed to sync token file: {e}")))?;

        Ok(DaemonToken(token))
    }

    /// Load a token from the file at `path`.
    ///
    /// Reads exactly 32 bytes.  Returns an error if the file is missing,
    /// unreadable, or does not contain exactly 32 bytes.
    pub fn load(path: &Path) -> Result<DaemonToken, DaemonError> {
        let data = fs::read(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => DaemonError::Token(format!(
                "token file not found: {path}",
                path = path.display()
            )),
            _ => DaemonError::Token(format!(
                "failed to read token file {path}: {e}",
                path = path.display()
            )),
        })?;

        let len = data.len();
        let bytes: [u8; 32] = data.try_into().map_err(|_| {
            DaemonError::Token(format!("invalid token size: expected 32 bytes, got {len}",))
        })?;

        Ok(DaemonToken(bytes))
    }

    /// Constant-time comparison of an expected token with received bytes.
    ///
    /// Returns `true` if `received` is exactly 32 bytes long **and** its
    /// contents match `expected`.  Uses `subtle::ConstantTimeEq` to
    /// prevent timing side-channels.
    pub fn verify(expected: &DaemonToken, received: &[u8]) -> bool {
        if received.len() != 32 {
            return false;
        }
        expected.0.ct_eq(received).into()
    }
}
