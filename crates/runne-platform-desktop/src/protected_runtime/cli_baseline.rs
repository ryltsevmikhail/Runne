use std::os::fd::AsFd as _;
use std::os::unix::ffi::OsStrExt as _;

use rustix::fs::{AtFlags, Dir, Mode, OFlags, open, openat, statat};
use rustix::io::Errno;

/// Allows an explicit Linux CLI runtime root only while legacy containers are absent.
///
/// This is read-only. The caller must still construct a launch spec and use its
/// existing executable and runtime-root validation before launching the daemon.
///
/// # Errors
///
/// Returns `RuntimeRootUnavailable` for a malformed path, an unsafe parent or
/// root, any legacy container, or any filesystem error other than `NotFound`.
pub fn require_linux_cli_baseline_root(
    runtime_root: &Path,
) -> Result<(), ProtectedBundledRuntimeError> {
    let unavailable = ProtectedBundledRuntimeError::RuntimeRootUnavailable;
    let path = runtime_root.as_os_str().as_bytes();
    if path.len() < 2
        || path[0] != b'/'
        || path[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(unavailable);
    }

    let parent = runtime_root.parent().ok_or(unavailable)?;
    if parent.file_name().is_none() || std::fs::canonicalize(parent).ok().as_deref() != Some(parent)
    {
        return Err(unavailable);
    }
    validate_owner_private_cli_directory(parent)?;
    let parent_fd = File::from(
        open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| unavailable)?,
    );
    let parent_before = parent_fd.metadata().map_err(|_| unavailable)?;
    validate_owner_private_cli_metadata(&parent_before)?;
    let root_name = runtime_root.file_name().ok_or(unavailable)?;
    let root = match openat(
        &parent_fd,
        root_name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => {
            let directory = File::from(directory);
            let metadata = directory.metadata().map_err(|_| unavailable)?;
            validate_owner_private_cli_metadata(&metadata)?;
            Some((directory, metadata))
        }
        Err(Errno::NOENT) => None,
        Err(_) => return Err(unavailable),
    };
    if let Some((root, _)) = &root {
        require_updates_absent(root)?;
    }

    require_updates_absent(&parent_fd)?;
    require_empty_native_enrollment_absent_or_private(&parent_fd)?;
    require_updates_absent(&parent_fd)?;
    require_empty_native_enrollment_absent_or_private(&parent_fd)?;
    match root {
        Some((root, before)) => {
            require_updates_absent(&root)?;
            let after = root.metadata().map_err(|_| unavailable)?;
            if metadata_identity(&before) != metadata_identity(&after) {
                return Err(unavailable);
            }
            let named_again = File::from(
                openat(
                    &parent_fd,
                    root_name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| unavailable)?,
            );
            let named_metadata = named_again.metadata().map_err(|_| unavailable)?;
            if metadata_identity(&before) != metadata_identity(&named_metadata) {
                return Err(unavailable);
            }
        }
        None => match openat(
            &parent_fd,
            root_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Err(Errno::NOENT) => {}
            _ => return Err(unavailable),
        },
    }
    let parent_after = std::fs::symlink_metadata(parent).map_err(|_| unavailable)?;
    if metadata_identity(&parent_before) != metadata_identity(&parent_after) {
        return Err(unavailable);
    }
    Ok(())
}

fn validate_owner_private_cli_directory(path: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    validate_owner_private_cli_metadata(&metadata)
}

fn validate_owner_private_cli_metadata(
    metadata: &std::fs::Metadata,
) -> Result<(), ProtectedBundledRuntimeError> {
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
    }
    Ok(())
}

fn require_updates_absent(parent: &File) -> Result<(), ProtectedBundledRuntimeError> {
    match statat(parent, "updates", AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(()),
        _ => Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable),
    }
}

fn require_empty_native_enrollment_absent_or_private(
    parent: &File,
) -> Result<(), ProtectedBundledRuntimeError> {
    let unavailable = ProtectedBundledRuntimeError::RuntimeRootUnavailable;
    let directory = match openat(
        parent,
        ".runne-native-enrollment",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => File::from(directory),
        Err(Errno::NOENT) => return Ok(()),
        Err(_) => return Err(unavailable),
    };
    let before = directory.metadata().map_err(|_| unavailable)?;
    if !before.is_dir()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o7777 != 0o700
    {
        return Err(unavailable);
    }
    let mut entries = Dir::read_from(directory.as_fd()).map_err(|_| unavailable)?;
    for entry in &mut entries {
        let entry = entry.map_err(|_| unavailable)?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Err(unavailable);
        }
    }
    let after = directory.metadata().map_err(|_| unavailable)?;
    if metadata_identity(&before) != metadata_identity(&after) {
        return Err(unavailable);
    }
    let named_again = File::from(
        openat(
            parent,
            ".runne-native-enrollment",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| unavailable)?,
    );
    let named_metadata = named_again.metadata().map_err(|_| unavailable)?;
    if metadata_identity(&before) != metadata_identity(&named_metadata) {
        return Err(unavailable);
    }
    Ok(())
}

fn metadata_identity(
    metadata: &std::fs::Metadata,
) -> (u64, u64, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[cfg(test)]
mod cli_baseline_tests {
    use super::*;

    include!("cli_baseline_tests.rs");
}
