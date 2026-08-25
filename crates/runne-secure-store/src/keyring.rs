mod anchor;
mod journal;
mod provider;
mod provider_delete;
#[cfg(test)]
mod provider_delete_tests;
mod tail;

use std::sync::Mutex;

use keyring::{Entry, Error as KeyringError};
use runne_provider::NativeCredentialAuthority;
use zeroize::Zeroizing;

use crate::SecureStoreError;

pub const ANCHOR_SERVICE: &str = "dev.runne.security-anchor.v1";
pub const LOCK_ACCOUNT: &str = "profile-lock";
pub const SECURITY_ANCHOR_MAGIC: &[u8; 8] = b"GCSA1\0\0\0";
pub const MAX_PROFILE_KEY_BYTES: usize = 128;
pub static KEYRING_LOCK: Mutex<()> = Mutex::new(());

/// Native secure-store backend for Linux Secret Service/keyutils and Windows
/// Credential Manager. The OS owns encryption and persistence; the encoded
/// payloads retain Runne's binding and corruption checks.
pub struct NativeKeyringStore {
    pub(super) profile_id: String,
    pub(super) anchor_profile: Option<[u8; 32]>,
    pub(super) version_authority: Option<NativeCredentialAuthority>,
}

impl NativeKeyringStore {
    #[must_use]
    pub fn new() -> Self {
        Self::with_profile_id("default")
    }

    #[must_use]
    pub fn with_profile_id(profile_id: impl AsRef<str>) -> Self {
        Self {
            profile_id: profile_id.as_ref().to_owned(),
            anchor_profile: None,
            version_authority: None,
        }
    }

    #[must_use]
    pub fn for_security_profile(profile_id: impl AsRef<str>, profile: [u8; 32]) -> Self {
        Self {
            profile_id: profile_id.as_ref().to_owned(),
            anchor_profile: Some(profile),
            version_authority: None,
        }
    }

    #[must_use]
    pub fn new_versioned(authority: NativeCredentialAuthority) -> Self {
        Self {
            version_authority: Some(authority),
            ..Self::new()
        }
    }

    pub(super) fn entry(service: &str, account: &str) -> Result<Entry, SecureStoreError> {
        Entry::new(service, account).map_err(|_| SecureStoreError::Unavailable)
    }

    pub(super) fn read_secret(
        service: &str,
        account: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        match Self::entry(service, account)?.get_secret() {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(_) => Err(SecureStoreError::Unavailable),
        }
    }

    pub(super) fn write_secret(
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), SecureStoreError> {
        Self::entry(service, account)?
            .set_secret(secret)
            .map_err(|_| SecureStoreError::OperationFailed("native secure-store write".into()))
    }

    pub(super) fn delete_secret(service: &str, account: &str) -> Result<(), SecureStoreError> {
        match Self::entry(service, account)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(_) => Err(SecureStoreError::OperationFailed(
                "native secure-store delete".into(),
            )),
        }
    }

    pub(super) fn anchor_account(&self) -> String {
        format!("anchor:{}", self.profile_id)
    }

    pub(super) fn lock_account(&self) -> String {
        format!("{}:{}", LOCK_ACCOUNT, self.profile_id)
    }

    pub(super) fn require_profile(&self, profile: [u8; 32]) -> Result<(), SecureStoreError> {
        (self.anchor_profile == Some(profile))
            .then_some(())
            .ok_or(SecureStoreError::LockMismatch)
    }
}

impl Default for NativeKeyringStore {
    fn default() -> Self {
        Self::new()
    }
}
