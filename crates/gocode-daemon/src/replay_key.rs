//! Owner-only stable replay-integrity key lifecycle.

use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// A stable, non-published key for replay cursor and gap integrity HMACs.
pub struct ReplayIntegrityKey([u8; 32]);

impl ReplayIntegrityKey {
    /// Derives an HMAC-SHA-256 integrity value for one replay artifact.
    pub fn derive_hmac(&self, message: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("fixed HMAC key length");
        mac.update(message);
        mac.finalize().into_bytes().into()
    }

    pub(crate) fn sidecar_digest(&self) -> [u8; 32] {
        use sha2::Digest;

        sha2::Sha256::digest(self.0).into()
    }
}

/// Redacted failures from replay-integrity-key lifecycle operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayIntegrityKeyError {
    /// The key file was not exactly 32 bytes.
    InvalidLength,
    /// A filesystem operation failed.
    Io,
}

impl std::fmt::Display for ReplayIntegrityKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLength => "invalid replay-integrity key length",
            Self::Io => "replay-integrity key I/O failure",
        })
    }
}

impl std::error::Error for ReplayIntegrityKeyError {}

/// Stateless owner-only replay-integrity-key lifecycle manager.
pub struct ReplayIntegrityKeyManager;

impl ReplayIntegrityKeyManager {
    /// Loads the existing key or provisions an exact 32-byte owner-only key.
    pub fn load_or_provision(path: &Path) -> Result<ReplayIntegrityKey, ReplayIntegrityKeyError> {
        match Self::load(path) {
            Ok(key) => Ok(key),
            Err(ReplayIntegrityKeyError::Io) if !path.exists() => Self::provision(path),
            Err(error) => Err(error),
        }
    }

    /// Loads an already-established key without provisioning a replacement.
    pub fn load_existing(path: &Path) -> Result<ReplayIntegrityKey, ReplayIntegrityKeyError> {
        Self::load(path)
    }

    fn provision(path: &Path) -> Result<ReplayIntegrityKey, ReplayIntegrityKeyError> {
        let parent = path.parent().ok_or(ReplayIntegrityKeyError::Io)?;
        fs::create_dir_all(parent).map_err(|_| ReplayIntegrityKeyError::Io)?;
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(crate::lock::O_NOFOLLOW_VAL);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(_) if path.exists() => return Self::load(path),
            Err(_) => return Err(ReplayIntegrityKeyError::Io),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| ReplayIntegrityKeyError::Io)?;
        }
        file.write_all(&bytes)
            .map_err(|_| ReplayIntegrityKeyError::Io)?;
        file.sync_all().map_err(|_| ReplayIntegrityKeyError::Io)?;
        Ok(ReplayIntegrityKey(bytes))
    }

    fn load(path: &Path) -> Result<ReplayIntegrityKey, ReplayIntegrityKeyError> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(crate::lock::O_NOFOLLOW_VAL);
        }
        let mut file = options
            .open(path)
            .map_err(|_| ReplayIntegrityKeyError::Io)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| ReplayIntegrityKeyError::Io)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ReplayIntegrityKeyError::InvalidLength)?;
        Ok(ReplayIntegrityKey(bytes))
    }
}
