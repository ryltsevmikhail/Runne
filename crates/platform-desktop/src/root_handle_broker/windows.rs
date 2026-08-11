use std::path::Path;

use gocode_api::RootHandleTransferAuthenticator;

use super::{RootHandleBrokerError, RootHandleTransferBinding, VerifiedRootHandle};

/// Windows transfer requires a brokered `DuplicateHandle` receiver tied to an
/// authenticated daemon process. Until that receiver is linked, reject every
/// operation rather than falling back to paths or inheritable handles.
pub(super) struct NativeDirectoryHandle;
pub(super) struct NativeTransferChannel;

pub(super) fn open_directory(_path: &Path) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
    Err(RootHandleBrokerError::Unavailable)
}

pub(super) fn open_relative_directory(
    _root: &NativeDirectoryHandle,
    _path: &Path,
) -> Result<(), RootHandleBrokerError> {
    Err(RootHandleBrokerError::Unavailable)
}

pub(super) fn send(
    _channel: NativeTransferChannel,
    _root: &VerifiedRootHandle,
    _authenticator: &RootHandleTransferAuthenticator,
    _binding: &RootHandleTransferBinding,
) -> Result<(), RootHandleBrokerError> {
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

#[allow(dead_code)]
pub(super) fn requires_brokered_duplicate_handle(
    _authenticator: &RootHandleTransferAuthenticator,
) -> Result<(), RootHandleBrokerError> {
    Err(RootHandleBrokerError::Unavailable)
}
