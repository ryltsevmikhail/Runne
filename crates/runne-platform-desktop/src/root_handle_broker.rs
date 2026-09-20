use std::fmt;
use std::path::{Component, Path};

use runne_api::RootHandleTransferAuthenticator;
use thiserror::Error;

mod editor;
mod files;
mod process_files;
pub use files::{RootFileEntry, RootFileKind};
pub use process_files::NativeProcessFiles;
#[cfg(unix)]
#[path = "root_handle_broker/unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "root_handle_broker/windows.rs"]
mod platform;
#[cfg(not(any(unix, windows)))]
compile_error!("root-handle broker requires a supported desktop platform");
#[cfg(all(unix, feature = "protected-channel-integration"))]
#[path = "root_handle_broker/endpoint.rs"]
mod endpoint;
#[cfg(all(windows, feature = "protected-channel-integration"))]
#[path = "root_handle_broker/windows_endpoint.rs"]
mod endpoint;
#[cfg(all(any(unix, windows), feature = "protected-channel-integration"))]
pub use endpoint::ProtectedRootHandleEndpoint;

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
struct StableFilesystemIdentity {
    digest: [u8; 32],
    device: u64,
}

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
        self.identity.digest == other.identity.digest
    }

    /// Returns the non-secret stable identity digest for protected root admission binding.
    #[must_use]
    pub const fn filesystem_identity_digest(&self) -> [u8; 32] {
        self.identity.digest
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

/// Exact native channel and launch context bound into one transfer transcript.
#[derive(Clone)]
#[cfg_attr(windows, allow(dead_code))]
pub struct RootHandleTransferBinding {
    channel_id: [u8; 16],
    launch_generation: u64,
    sender_pid: u32,
    receiver_pid: u32,
    peer_uid: u32,
    offer_digest: [u8; 32],
    verify_receiver_kernel_peer: bool,
}

impl RootHandleTransferBinding {
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_binding(
        channel_id: [u8; 16],
        launch_generation: u64,
        sender_pid: u32,
        receiver_pid: u32,
        peer_uid: u32,
    ) -> Result<Self, RootHandleBrokerError> {
        if channel_id == [0; 16] || launch_generation == 0 {
            return Err(RootHandleBrokerError::Rejected);
        }
        Ok(Self {
            channel_id,
            launch_generation,
            sender_pid,
            receiver_pid,
            peer_uid,
            offer_digest: [1; 32],
            verify_receiver_kernel_peer: true,
        })
    }
}

#[cfg(all(unix, feature = "protected-channel-integration"))]
fn binding_for_protected_control(
    context: &runne_api::RootHandleTransferContext,
    offer_digest: [u8; 32],
) -> Result<RootHandleTransferBinding, RootHandleBrokerError> {
    if offer_digest == [0; 32] {
        return Err(RootHandleBrokerError::Rejected);
    }
    Ok(RootHandleTransferBinding {
        channel_id: *context.transfer_id(),
        launch_generation: context.launch_generation(),
        sender_pid: context.sender_pid(),
        receiver_pid: context.receiver_pid(),
        peer_uid: context.effective_uid(),
        offer_digest,
        // An inherited socketpair's kernel peer remains its creator (desktop),
        // not the post-fork daemon child. READY proves the logical child tuple.
        verify_receiver_kernel_peer: false,
    })
}

impl fmt::Debug for RootHandleTransferBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootHandleTransferBinding(<redacted>)")
    }
}

/// One-shot authenticated sender. It owns and closes its channel after one call.
pub struct RootHandleTransferSender {
    channel: Option<platform::NativeTransferChannel>,
    authenticator: RootHandleTransferAuthenticator,
    binding: RootHandleTransferBinding,
}

/// One-shot authenticated receiver. It issues the challenge before accepting an FD.
pub struct RootHandleTransferReceiver {
    channel: Option<platform::NativeTransferChannel>,
    authenticator: RootHandleTransferAuthenticator,
    binding: RootHandleTransferBinding,
}

impl RootHandleTransferSender {
    /// Sends exactly one real directory handle after receiving a receiver challenge.
    ///
    /// # Errors
    ///
    /// Returns a closed error if the platform transport cannot transfer the handle.
    pub fn transfer(mut self, root: &VerifiedRootHandle) -> Result<(), RootHandleBrokerError> {
        platform::send(
            self.channel.take().ok_or(RootHandleBrokerError::Rejected)?,
            root,
            &self.authenticator,
            &self.binding,
        )
    }
}

impl RootHandleTransferReceiver {
    /// Issues a challenge and receives exactly one authenticated directory handle.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed records, proof failures, replay, or handle mismatch.
    pub fn receive(mut self) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
        platform::receive(
            self.channel.take().ok_or(RootHandleBrokerError::Rejected)?,
            &self.authenticator,
            &self.binding,
        )
    }
}

#[cfg(feature = "test-support")]
mod transfer_test_support;
#[cfg(feature = "test-support")]
pub use transfer_test_support::test_transfer_pair;
#[cfg(all(unix, feature = "test-support"))]
pub use transfer_test_support::{
    launcher_spawn_attempt_count, test_transfer_receiver, test_transfer_sender,
};

impl fmt::Debug for RootHandleTransferSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootHandleTransferSender")
            .field("authentication", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn safe_path(path: &Path) -> bool {
    path.is_absolute()
        && !path.as_os_str().is_empty()
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
