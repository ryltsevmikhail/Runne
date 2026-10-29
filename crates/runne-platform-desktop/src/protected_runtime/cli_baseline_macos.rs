// macOS owner-private runtime-root baseline.
//
// The Linux baseline additionally rejects legacy containers and update
// directories that only exist in the Linux packaging layout. macOS has no
// equivalent layout: the runtime root is the per-user state directory under
// `~/Library/Application Support`, so the portable invariant is the one that
// matters here: a real, non-aliased, owner-only directory whose parent is not
// writable by any other user.

use std::os::unix::ffi::OsStrExt as _;

/// Allows only an existing, owner-private runtime root on macOS.
///
/// This is read-only and deliberately narrower than the Linux baseline: it
/// checks identity and permissions, never a packaging layout.
///
/// # Errors
///
/// Returns `RuntimeRootUnavailable` for a relative or dot-segment path, an
/// aliased root, a symlink, a non-directory, a foreign owner, or permissions
/// that grant group/other access.
pub fn require_terminal_baseline_root(
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
    let parent_metadata = std::fs::metadata(parent).map_err(|_| unavailable)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != rustix::process::geteuid().as_raw()
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(unavailable);
    }
    let metadata = std::fs::symlink_metadata(runtime_root).map_err(|_| unavailable)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(unavailable);
    }
    if runtime_root.canonicalize().ok().as_deref() != Some(runtime_root) {
        return Err(unavailable);
    }
    Ok(())
}
