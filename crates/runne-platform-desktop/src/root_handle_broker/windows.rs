use std::path::{Path, PathBuf};

use runne_api::RootHandleTransferAuthenticator;
use runne_windows_native_handle::{DirectoryHandle, NativeDirectoryEntryKind, NativeHandleError};

use super::{
    RootHandleBrokerError, RootHandleTransferBinding, StableFilesystemIdentity, VerifiedRootHandle,
};

impl VerifiedRootHandle {
    pub(crate) const fn native_handle(&self) -> &DirectoryHandle {
        &self.handle
    }

    pub(crate) fn from_native_handle(handle: DirectoryHandle) -> Self {
        Self {
            identity: StableFilesystemIdentity {
                digest: handle.identity().digest(),
                device: 0,
            },
            handle,
        }
    }
}

pub(super) fn list_relative(
    root: &NativeDirectoryHandle,
    path: &Path,
    limit: usize,
) -> Result<Vec<super::files::RootFileEntry>, RootHandleBrokerError> {
    let native_path = canonical_path(path)?;
    let entries = if native_path.as_os_str().is_empty() {
        root.list_entries(limit)
    } else {
        root.list_relative_entries(&native_path, limit)
    }
    .map_err(map_native_error)?;
    entries
        .into_iter()
        .map(|entry| {
            let name = entry
                .name()
                .to_str()
                .ok_or(RootHandleBrokerError::Rejected)?;
            let relative_path = if path.as_os_str().is_empty() {
                name.to_owned()
            } else {
                format!("{}/{name}", path.display())
            };
            let kind = match entry.kind() {
                NativeDirectoryEntryKind::File => super::files::RootFileKind::File,
                NativeDirectoryEntryKind::Directory => super::files::RootFileKind::Directory,
            };
            Ok(super::files::entry(relative_path, kind, entry.size_bytes()))
        })
        .collect()
}

pub(super) fn list_root(
    root: &NativeDirectoryHandle,
    limit: usize,
) -> Result<Vec<super::files::RootFileEntry>, RootHandleBrokerError> {
    list_relative(root, Path::new(""), limit)
}

pub(super) fn clone_root(
    root: &VerifiedRootHandle,
) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
    Ok(verified_from_handle(
        root.handle
            .try_clone()
            .map_err(|_| RootHandleBrokerError::Unavailable)?,
    ))
}

pub(super) fn read_text_relative(
    root: &NativeDirectoryHandle,
    path: &Path,
    maximum_bytes: usize,
) -> Result<String, RootHandleBrokerError> {
    let native_path = canonical_path(path)?;
    let bytes = root
        .read_relative_file(&native_path, maximum_bytes)
        .map_err(map_native_error)?;
    String::from_utf8(bytes).map_err(|_| RootHandleBrokerError::Rejected)
}

/// Windows handles live behind the audited target-gated native shim.
pub(super) type NativeDirectoryHandle = DirectoryHandle;

pub(super) struct NativeProcessFiles {
    inner: runne_windows_native_handle::ProcessFiles,
}

pub(super) fn open_process_files(
    root: &NativeDirectoryHandle,
    executable: &Path,
    cwd: &Path,
) -> Result<NativeProcessFiles, RootHandleBrokerError> {
    // The native validator accepts backslash separators only; process
    // material arrives with the same `/`-joined shapes as file reads.
    root.open_process_files(&canonical_path(executable)?, &canonical_path(cwd)?)
        .map(|inner| NativeProcessFiles { inner })
        .map_err(map_native_error)
}

pub(super) mod editor {
    include!("windows_editor.rs");
}

pub(super) fn launch_system_default_editor(
    root: &NativeDirectoryHandle,
    relative_path: &Path,
) -> Result<(), RootHandleBrokerError> {
    editor::launch_system_default_editor(root, relative_path)
}

pub(super) fn executable_command_path(files: &NativeProcessFiles) -> std::path::PathBuf {
    files.inner.executable_path().to_owned()
}

pub(super) fn cwd_command_path(files: &NativeProcessFiles) -> std::path::PathBuf {
    files.inner.cwd_path().to_owned()
}

pub(super) const fn executable_content_digest(files: &NativeProcessFiles) -> [u8; 32] {
    files.inner.executable_content_digest()
}

pub(super) const fn executable_filesystem_identity_digest(files: &NativeProcessFiles) -> [u8; 32] {
    files.inner.executable_identity_digest()
}

pub(super) const fn cwd_filesystem_identity_digest(files: &NativeProcessFiles) -> [u8; 32] {
    files.inner.cwd_identity_digest()
}

/// The protected launcher channel is introduced with the daemon receiver in Slice B.
pub(super) struct NativeTransferChannel;

pub(super) fn open_directory(path: &Path) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
    Ok(verified_from_handle(
        DirectoryHandle::open(path).map_err(|_| RootHandleBrokerError::Rejected)?,
    ))
}

pub(super) fn open_relative_directory(
    root: &NativeDirectoryHandle,
    path: &Path,
) -> Result<(), RootHandleBrokerError> {
    root.open_relative_directory(path)
        .map(|_| ())
        .map_err(|_| RootHandleBrokerError::Rejected)
}

pub(super) const fn send(
    _channel: NativeTransferChannel,
    _root: &VerifiedRootHandle,
    _authenticator: &RootHandleTransferAuthenticator,
    _binding: &RootHandleTransferBinding,
) -> Result<(), RootHandleBrokerError> {
    // No token is emitted until Slice B binds the exact protected daemon child.
    Err(RootHandleBrokerError::Unavailable)
}

pub(super) const fn receive(
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

fn verified_from_handle(handle: DirectoryHandle) -> VerifiedRootHandle {
    let identity = StableFilesystemIdentity {
        digest: handle.identity().digest(),
        device: 0,
    };
    VerifiedRootHandle { handle, identity }
}

fn canonical_path(path: &Path) -> Result<PathBuf, RootHandleBrokerError> {
    let value = path.to_str().ok_or(RootHandleBrokerError::Rejected)?;
    if value.is_empty() {
        return Ok(PathBuf::new());
    }
    Ok(PathBuf::from(value.replace('/', "\\")))
}

const fn map_native_error(error: NativeHandleError) -> RootHandleBrokerError {
    match error {
        NativeHandleError::Rejected | NativeHandleError::TargetMismatch => {
            RootHandleBrokerError::Rejected
        }
        NativeHandleError::Unavailable => RootHandleBrokerError::Unavailable,
    }
}
