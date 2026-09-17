//! Fixture-owned writer stderr log for the local native enrollment tests.
//!
//! The writer's stderr used to be opened by the spawned child at a
//! predictable `/tmp` path, which any local peer could pre-create as a
//! symlink. The parent now validates the fixture namespace and opens the
//! append-only log itself with `O_NOFOLLOW`, checks the descriptor stat
//! (regular file, current uid, exact 0600 mode) before any byte can be
//! written, duplicates the descriptor above the reserved 0..=3 range so it
//! can never collide with the bootstrap/stdin or fd 3 handoff slots, and
//! hands the child the already-open descriptor. The log path is derived per
//! call from the validated fixture root — there is no runtime-mutable
//! global log path. Production keeps `/dev/null`.
//!
//! Scope of the guarantee: the fixture root and its parent must be
//! non-symlink directories owned by the current uid with no group/other
//! permission bits. That intentionally fails closed on world-writable
//! parents such as `/tmp` (mode 01777); callers must point the fixture root
//! at a private per-user namespace (macOS `$TMPDIR` qualifies). The opened
//! file itself is pinned by `O_NOFOLLOW` plus an fstat on the returned
//! descriptor; same-uid swaps of intermediate path components between the
//! namespace stat checks and the open are NOT claimed closed.

use std::path::Path;

use super::BrokerHandoffError;

/// Opens the fixture-owned append log after validating the whole namespace,
/// returning a descriptor numbered above the reserved 0..=3 range.
///
/// # Errors
///
/// Returns [`BrokerHandoffError::Rejected`] whenever any check fails; the
/// caller must fail closed instead of falling back to another location.
#[cfg(feature = "test-support")]
pub(super) fn open_fixture_writer_stderr_log(
    fixture_root: &Path,
) -> Result<std::os::fd::OwnedFd, BrokerHandoffError> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;

    const LOG_FILE_NAME: &str = "writer-stderr.log";

    validate_fixture_root(fixture_root)?;
    let log_path = fixture_root.join(LOG_FILE_NAME);
    let descriptor = open(
        &log_path,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_APPEND | OFlag::O_NOFOLLOW,
        Mode::from_bits_retain(0o600),
    )
    .map_err(|_| BrokerHandoffError::Rejected)?;
    // Never hand out a descriptor that could collide with stdin/stdout/
    // stderr or the fd 3 secret slot used by the spawn actions.
    let raised = rustix::io::fcntl_dupfd_cloexec(&descriptor, 4)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    match verify_log_descriptor(&raised) {
        Ok(()) => Ok(raised),
        // Both descriptors close themselves on drop; nothing was written.
        Err(rejected) => Err(rejected),
    }
}

#[cfg(feature = "test-support")]
fn validate_fixture_root(root: &Path) -> Result<(), BrokerHandoffError> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let root_metadata =
        std::fs::symlink_metadata(root).map_err(|_| BrokerHandoffError::Rejected)?;
    if root_metadata.is_symlink() || !root_metadata.is_dir() {
        return Err(BrokerHandoffError::Rejected);
    }
    let parent = root.parent().ok_or(BrokerHandoffError::Rejected)?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_| BrokerHandoffError::Rejected)?;
    if parent_metadata.is_symlink() || !parent_metadata.is_dir() {
        return Err(BrokerHandoffError::Rejected);
    }
    let expected_uid = current_euid();
    if root_metadata.uid() != expected_uid || parent_metadata.uid() != expected_uid {
        return Err(BrokerHandoffError::Rejected);
    }
    if root_metadata.permissions().mode() & 0o077 != 0
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BrokerHandoffError::Rejected);
    }
    Ok(())
}

#[cfg(feature = "test-support")]
fn verify_log_descriptor(descriptor: &std::os::fd::OwnedFd) -> Result<(), BrokerHandoffError> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let file = std::fs::File::from(
        descriptor
            .try_clone()
            .map_err(|_| BrokerHandoffError::Rejected)?,
    );
    let metadata = file.metadata().map_err(|_| BrokerHandoffError::Rejected)?;
    if !metadata.is_file() {
        return Err(BrokerHandoffError::Rejected);
    }
    if metadata.uid() != current_euid() {
        return Err(BrokerHandoffError::Rejected);
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(BrokerHandoffError::Rejected);
    }
    Ok(())
}

#[cfg(feature = "test-support")]
fn current_euid() -> u32 {
    nix::unistd::geteuid().as_raw()
}
