use std::path::Path;

use gocode_api::RootHandleTransferAuthenticator;
use gocode_windows_native_handle::DirectoryHandle;

use super::{
    RootHandleBrokerError, RootHandleTransferBinding, StableFilesystemIdentity, VerifiedRootHandle,
};

/// Windows handles live behind the audited target-gated native shim.
pub(super) type NativeDirectoryHandle = DirectoryHandle;

/// The protected launcher channel is introduced with the daemon receiver in Slice B.
pub(super) struct NativeTransferChannel;

pub(super) fn open_directory(path: &Path) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
    verified_from_handle(DirectoryHandle::open(path).map_err(|_| RootHandleBrokerError::Rejected)?)
}

pub(super) fn open_relative_directory(
    root: &NativeDirectoryHandle,
    path: &Path,
) -> Result<(), RootHandleBrokerError> {
    root.open_relative_directory(path)
        .map(|_| ())
        .map_err(|_| RootHandleBrokerError::Rejected)
}

pub(super) fn send(
    _channel: NativeTransferChannel,
    _root: &VerifiedRootHandle,
    _authenticator: &RootHandleTransferAuthenticator,
    _binding: &RootHandleTransferBinding,
) -> Result<(), RootHandleBrokerError> {
    // No token is emitted until Slice B binds the exact protected daemon child.
    Err(RootHandleBrokerError::Unavailable)
}

pub(super) fn receive(
    _channel: NativeTransferChannel,
    _authenticator: &RootHandleTransferAuthenticator,
    _binding: &RootHandleTransferBinding,
) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
    Err(RootHandleBrokerError::Unavailable)
}

#[cfg(feature = "test-support")]
pub(super) fn test_pair()
-> Result<(NativeTransferChannel, NativeTransferChannel), RootHandleBrokerError> {
    Err(RootHandleBrokerError::Unavailable)
}

fn verified_from_handle(
    handle: DirectoryHandle,
) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
    let identity = StableFilesystemIdentity {
        digest: handle.identity().digest(),
        device: 0,
    };
    Ok(VerifiedRootHandle { handle, identity })
}
