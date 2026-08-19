#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
use std::cell::Cell;
use std::os::fd::OwnedFd;

#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::fs::{AtFlags, fsync, linkat};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};

use super::fs::{FsBrokerError, FsIdentity};

pub(super) struct UnixResolution {
    pub file_fd: OwnedFd,
}

pub(super) struct UnixParent {
    pub directory: OwnedFd,
    pub final_name: String,
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
thread_local! {
    static FAIL_NEXT_COMMIT: Cell<bool> = const { Cell::new(false) };
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
pub(super) fn fail_next_commit_for_test() {
    FAIL_NEXT_COMMIT.with(|fail| fail.set(true));
}

pub(super) fn open_root(path: &std::path::Path) -> Result<(OwnedFd, FsIdentity), FsBrokerError> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(map_open_error)?;
    let stat = fstat(&fd).map_err(io_error)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(FsBrokerError::NotDirectory);
    }
    Ok((fd, identity(&stat)?))
}

pub(super) fn root_is_admitted(fd: &OwnedFd, expected: &FsIdentity) -> Result<(), FsBrokerError> {
    let stat = fstat(fd).map_err(io_error)?;
    (FileType::from_raw_mode(stat.st_mode).is_dir() && identity(&stat)? == *expected)
        .then_some(())
        .ok_or(FsBrokerError::IdentityMismatch)
}

pub(super) fn resolve_nofollow(
    root: &OwnedFd,
    components: &[String],
    final_flags: OFlags,
) -> Result<UnixResolution, FsBrokerError> {
    let parent = parent_nofollow(root, components)?;
    let fd = openat(
        &parent.directory,
        parent.final_name.as_str(),
        final_flags | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(map_open_error)?;
    let kind = FileType::from_raw_mode(fstat(&fd).map_err(io_error)?.st_mode);
    if !kind.is_file() && !kind.is_dir() {
        return Err(FsBrokerError::PermissionDenied);
    }
    Ok(UnixResolution { file_fd: fd })
}

pub(super) fn parent_nofollow(
    root: &OwnedFd,
    components: &[String],
) -> Result<UnixParent, FsBrokerError> {
    let (final_name, parents) = components
        .split_last()
        .ok_or(FsBrokerError::PathNotRelative)?;
    let mut directory = rustix::io::fcntl_dupfd_cloexec(root, 0).map_err(io_error)?;
    let root_device = fstat(&directory).map_err(io_error)?.st_dev;
    for component in parents {
        let opened = openat(
            &directory,
            component.as_str(),
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(map_open_error)?;
        let stat = fstat(&opened).map_err(io_error)?;
        if stat.st_dev != root_device {
            return Err(FsBrokerError::PathEscapesRoot);
        }
        directory = opened;
    }
    Ok(UnixParent {
        directory,
        final_name: final_name.clone(),
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn create_unnamed(parent: &OwnedFd) -> Result<OwnedFd, FsBrokerError> {
    openat(
        parent,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::OPNOTSUPP {
            FsBrokerError::MutationUnavailable
        } else {
            io_error(error)
        }
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(super) fn create_unnamed(_: &OwnedFd) -> Result<OwnedFd, FsBrokerError> {
    Err(FsBrokerError::BackendUnavailable)
}

pub(super) fn ensure_absent(parent: &OwnedFd, name: &str) -> Result<(), FsBrokerError> {
    match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(_) => Err(FsBrokerError::Io("destination already exists".into())),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(map_open_error(error)),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn commit_create(
    parent: &OwnedFd,
    staged: &OwnedFd,
    final_name: &str,
) -> Result<(), FsBrokerError> {
    fail_before_commit()?;
    linkat(staged, "", parent, final_name, AtFlags::EMPTY_PATH).map_err(io_error)?;
    fsync(parent).map_err(io_error)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(super) fn commit_create(_: &OwnedFd, _: &OwnedFd, _: &str) -> Result<(), FsBrokerError> {
    Err(FsBrokerError::BackendUnavailable)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn fail_before_commit() -> Result<(), FsBrokerError> {
    #[cfg(test)]
    if FAIL_NEXT_COMMIT.with(|fail| fail.replace(false)) {
        return Err(FsBrokerError::Io("injected staged-write failure".into()));
    }
    Ok(())
}

fn identity(stat: &rustix::fs::Stat) -> Result<FsIdentity, FsBrokerError> {
    #[allow(clippy::useless_conversion)]
    let device = u64::try_from(stat.st_dev)
        .map_err(|_| FsBrokerError::Io("negative device identity".into()))?;
    Ok(FsIdentity {
        inode: stat.st_ino,
        device,
    })
}

fn io_error(error: rustix::io::Errno) -> FsBrokerError {
    FsBrokerError::Io(error.to_string())
}

fn map_open_error(error: rustix::io::Errno) -> FsBrokerError {
    if error == rustix::io::Errno::NXIO {
        FsBrokerError::PermissionDenied
    } else if error == rustix::io::Errno::LOOP {
        FsBrokerError::SymlinkEscapesRoot
    } else if error == rustix::io::Errno::NOTDIR {
        FsBrokerError::NotDirectory
    } else {
        io_error(error)
    }
}
