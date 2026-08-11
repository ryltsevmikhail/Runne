use std::collections::HashSet;
use std::fmt;
use std::path::{Component, Path};
use std::sync::Mutex;

use gocode_api::RootHandleTransferAuthenticator;
use rand::RngCore;
use thiserror::Error;

#[cfg(unix)]
#[path = "root_handle_broker/unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "root_handle_broker/windows.rs"]
mod platform;
#[cfg(not(any(unix, windows)))]
compile_error!("root-handle broker requires a supported desktop platform");

const TRANSFER_RECORD_BYTES: usize = 64;

/// Fail-closed errors for native root-handle selection and transfer.
#[derive(Debug, Error)]
pub enum RootHandleBrokerError {
    #[error("root handle rejected")]
    Rejected,
    #[error("root handle transport unavailable")]
    Unavailable,
}

/// Stable, native-only filesystem identity for one open directory.
#[derive(PartialEq, Eq)]
struct StableFilesystemIdentity([u8; 32]);

impl fmt::Debug for StableFilesystemIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StableFilesystemIdentity(<redacted>)")
    }
}

/// An owned directory handle that never retains a path for later authorization.
pub struct VerifiedRootHandle {
    handle: platform::NativeDirectoryHandle,
    identity: StableFilesystemIdentity,
}

impl VerifiedRootHandle {
    /// Opens a directory without following its final symlink or reparse point.
    ///
    /// # Errors
    ///
    /// Returns a closed error for traversal, links, non-directories, and I/O failures.
    pub fn open(path: &Path) -> Result<Self, RootHandleBrokerError> {
        if !safe_path(path) {
            return Err(RootHandleBrokerError::Rejected);
        }
        platform::open_directory(path)
    }

    /// Opens a directory below this root using a handle-relative path only.
    ///
    /// # Errors
    ///
    /// Returns a closed error for traversal, links, non-directories, and I/O failures.
    pub fn open_relative_directory(&self, path: &Path) -> Result<(), RootHandleBrokerError> {
        if !safe_relative_path(path) {
            return Err(RootHandleBrokerError::Rejected);
        }
        platform::open_relative_directory(&self.handle, path)
    }

    /// Compares native filesystem identities without materializing either path.
    #[must_use]
    pub fn same_filesystem_object(&self, other: &Self) -> bool {
        self.identity == other.identity
    }

    /// Returns the non-secret stable identity digest for protected root admission binding.
    #[must_use]
    pub const fn filesystem_identity_digest(&self) -> [u8; 32] {
        self.identity.0
    }
}

impl fmt::Debug for VerifiedRootHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRootHandle")
            .field("handle", &"<redacted>")
            .field("directory", &"<redacted>")
            .field("identity", &self.identity)
            .finish()
    }
}

/// Authenticated broker for one-way native directory-handle transfers.
pub struct RootHandleBroker {
    authenticator: RootHandleTransferAuthenticator,
    used_nonces: Mutex<HashSet<[u8; 32]>>,
}

impl RootHandleBroker {
    #[must_use]
    pub fn new(authenticator: RootHandleTransferAuthenticator) -> Self {
        Self {
            authenticator,
            used_nonces: Mutex::new(HashSet::new()),
        }
    }

    /// Sends one real directory handle over the platform's authenticated broker.
    ///
    /// # Errors
    ///
    /// Returns a closed error if the platform transport cannot transfer the handle.
    #[cfg(unix)]
    pub fn send(
        &self,
        stream: &std::os::unix::net::UnixStream,
        root: &VerifiedRootHandle,
    ) -> Result<(), RootHandleBrokerError> {
        let mut nonce = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.send_with_nonce(stream, root, nonce)
    }

    /// Sends a transfer with a caller-owned nonce for a native protocol peer.
    ///
    /// Callers should use [`Self::send`] unless a receiver protocol supplies the nonce.
    ///
    /// # Errors
    ///
    /// Returns a closed error if the platform transport cannot transfer the handle.
    #[cfg(unix)]
    pub fn send_with_nonce(
        &self,
        stream: &std::os::unix::net::UnixStream,
        root: &VerifiedRootHandle,
        nonce: [u8; 32],
    ) -> Result<(), RootHandleBrokerError> {
        platform::send(stream, root, nonce, &self.authenticator)
    }

    /// Receives and authenticates one real directory handle.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed records, proof failures, replay, or handle mismatch.
    #[cfg(unix)]
    pub fn receive(
        &self,
        stream: &std::os::unix::net::UnixStream,
    ) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
        let (root, nonce) = platform::receive(stream, &self.authenticator)?;
        let mut used = self
            .used_nonces
            .lock()
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        if !used.insert(nonce) {
            return Err(RootHandleBrokerError::Rejected);
        }
        drop(used);
        Ok(root)
    }
}

impl fmt::Debug for RootHandleBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootHandleBroker")
            .field("authentication", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn safe_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

fn safe_relative_path(path: &Path) -> bool {
    !path.is_absolute()
        && !path.as_os_str().is_empty()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

fn transfer_record(
    nonce: &[u8; 32],
    identity: &StableFilesystemIdentity,
) -> [u8; TRANSFER_RECORD_BYTES] {
    let mut record = [0; TRANSFER_RECORD_BYTES];
    record[..32].copy_from_slice(nonce);
    record[32..].copy_from_slice(&identity.0);
    record
}
