//! Fail-closed authority artifact file operations.

use std::{
    fs::{File, Metadata, OpenOptions},
    io::Read as _,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
#[cfg(all(unix, any(test, target_os = "macos")))]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(any(test, target_os = "macos"))]
use std::{fs, io::Write as _, path::PathBuf};

use super::{CliError, MAX_ARTIFACT_BYTES};

pub(super) fn read_bounded(path: &Path) -> Result<Vec<u8>, CliError> {
    let file = open_read_nofollow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| CliError::AuthorityUnavailable)?;
    if !is_regular_non_reparse_file(&metadata) || metadata.len() > MAX_ARTIFACT_BYTES as u64 {
        return Err(CliError::AuthorityUnavailable);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| CliError::AuthorityUnavailable)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take((MAX_ARTIFACT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::AuthorityUnavailable)?;
    (bytes.len() <= MAX_ARTIFACT_BYTES)
        .then_some(bytes)
        .ok_or(CliError::AuthorityUnavailable)
}

#[cfg(any(test, target_os = "macos"))]
#[cfg_attr(not(unix), allow(unused_variables))]
pub(super) fn existing_exact(path: &Path, expected: &[u8], mode: u32) -> Result<bool, CliError> {
    let bytes = read_bounded(path)?;
    let metadata = path.metadata().map_err(|_| CliError::AuthorityArtifactIo)?;
    #[cfg(unix)]
    let mode_matches = metadata.permissions().mode() & 0o777 == mode;
    #[cfg(not(unix))]
    let mode_matches = true;
    Ok(bytes == expected && mode_matches)
}

#[cfg(any(test, target_os = "macos"))]
pub(super) fn create_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), CliError> {
    create_new_inner(path, bytes, mode, |parent, temporary| {
        let _ = sync_parent(parent);
        let _ = fs::remove_file(temporary);
        let _ = sync_parent(parent);
    })
}

#[cfg(all(test, unix))]
pub(super) fn create_new_with_failing_post_commit(
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), CliError> {
    create_new_inner(path, bytes, mode, |_, _| {
        let _ = Err::<(), _>(std::io::Error::from_raw_os_error(libc::EMFILE));
        let _ = Err::<(), _>(std::io::Error::other("injected directory sync failure"));
        let _ = Err::<(), _>(std::io::Error::other("injected cleanup failure"));
    })
}

#[cfg(any(test, target_os = "macos"))]
fn create_new_inner(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    post_commit: impl FnOnce(&Path, &Path),
) -> Result<(), CliError> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(CliError::AuthorityUnavailable);
    }
    let parent = path.parent().ok_or(CliError::AuthorityUnavailable)?;
    let temporary = unique_temporary_path(parent)?;
    let result = (|| {
        let mut file = open_new_nofollow(&temporary, mode)?;
        file.write_all(bytes)
            .and_then(|()| set_mode_and_sync(&file, mode))
            .map_err(|_| CliError::AuthorityUnavailable)?;
        validate_staged_file(&file, bytes.len(), mode)?;
        fs::hard_link(&temporary, path).map_err(|_| CliError::AuthorityUnavailable)?;
        // The already-open, exclusive temporary inode was fully written, mode-checked, and
        // synced before this hard-link commit point. No fallible reopen is needed afterwards.
        post_commit(parent, &temporary);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(any(test, target_os = "macos"))]
#[cfg_attr(not(unix), allow(unused_variables))]
fn validate_staged_file(file: &File, expected_len: usize, mode: u32) -> Result<(), CliError> {
    let metadata = file
        .metadata()
        .map_err(|_| CliError::AuthorityUnavailable)?;
    if !metadata.is_file()
        || metadata.len()
            != u64::try_from(expected_len).map_err(|_| CliError::AuthorityUnavailable)?
    {
        return Err(CliError::AuthorityUnavailable);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != mode {
        return Err(CliError::AuthorityUnavailable);
    }
    Ok(())
}

fn open_read_nofollow(path: &Path) -> Result<File, CliError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options
        .open(path)
        .map_err(|_| CliError::AuthorityUnavailable)
}

#[cfg(any(test, target_os = "macos"))]
fn open_new_nofollow(path: &Path, mode: u32) -> Result<File, CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    #[cfg(not(unix))]
    let _ = mode;
    options
        .open(path)
        .map_err(|_| CliError::AuthorityUnavailable)
}

#[cfg(any(test, target_os = "macos"))]
fn unique_temporary_path(parent: &Path) -> Result<PathBuf, CliError> {
    let mut random = [0_u8; 16];
    fill_random(&mut random)?;
    Ok(parent.join(format!(".runne-authority-{}.tmp", hex_bytes(&random))))
}

#[cfg(all(unix, any(test, target_os = "macos")))]
fn fill_random(bytes: &mut [u8]) -> Result<(), CliError> {
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(bytes))
        .map_err(|_| CliError::AuthorityUnavailable)
}

#[cfg(all(not(unix), any(test, target_os = "macos")))]
const fn fill_random(_: &mut [u8]) -> Result<(), CliError> {
    Err(CliError::AuthorityUnavailable)
}

#[cfg(any(test, target_os = "macos"))]
fn set_mode_and_sync(file: &File, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    #[cfg(not(unix))]
    let _ = mode;
    file.sync_all()
}

#[cfg(all(unix, any(test, target_os = "macos")))]
fn sync_parent(parent: &Path) -> Result<(), CliError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CliError::AuthorityUnavailable)
}

#[cfg(all(not(unix), any(test, target_os = "macos")))]
#[allow(clippy::unnecessary_wraps)] // signature parity with the unix fsync
const fn sync_parent(_parent: &Path) -> Result<(), CliError> {
    Ok(())
}

pub(super) fn is_link_or_reparse(path: &Path) -> Result<bool, CliError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| CliError::AuthorityUnavailable)?;
    Ok(metadata.file_type().is_symlink() || is_reparse_point(&metadata))
}

fn is_regular_non_reparse_file(metadata: &Metadata) -> bool {
    metadata.is_file() && !is_reparse_point(metadata)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
const fn is_reparse_point(_: &Metadata) -> bool {
    false
}

#[cfg(any(test, target_os = "macos"))]
fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}
