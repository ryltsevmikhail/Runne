//! Ownership-checked directory traversal for client-side state files.
//!
//! Shared by permission recovery and the terminal client so both apply the same
//! no-follow, owner and mode checks instead of keeping private copies.

use std::ffi::OsString;
use std::io;
use std::path::Path;

use rustix::fd::OwnedFd;
use rustix::fs::{FileType, Mode, OFlags, fstat, mkdirat, openat};
use rustix::io::Errno;
use rustix::process::geteuid;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Opens (optionally creates) one child directory without following symlinks.
pub(crate) fn open_directory(
    parent: &OwnedFd,
    name: &str,
    create: bool,
    private: bool,
) -> io::Result<Option<OwnedFd>> {
    let fd = match openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) if !create => return Ok(None),
        Err(Errno::NOENT) => {
            match mkdirat(parent, name, Mode::from(0o700)) {
                Ok(()) => {}
                Err(Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            openat(parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(io::Error::from)?
        }
        Err(error) => return Err(error.into()),
    };
    if private {
        validate_private_directory(&fd)?;
    } else {
        validate_ancestor_directory(&fd)?;
    }
    Ok(Some(fd))
}

/// Lists entry names of an already-validated directory path.
///
/// The names are discovery hints only: callers must resolve each one through an
/// open descriptor with `O_NOFOLLOW` (and re-validate the result), so a directory
/// swapped between validation and listing cannot redirect a lookup.
pub(crate) fn entry_names(path: &Path) -> io::Result<Vec<OsString>> {
    std::fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect()
}

/// Accepts a directory owned by root or the current user and not group-writable.
pub(crate) fn validate_ancestor_directory(fd: &OwnedFd) -> io::Result<()> {
    let stat = fstat(fd)?;
    let owner = geteuid().as_raw();
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_uid != 0 && stat.st_uid != owner)
        || stat.st_mode & 0o022 != 0
    {
        return Err(io::Error::other("insecure ancestor directory"));
    }
    Ok(())
}

/// Accepts only a directory owned by the current user with mode 0700.
pub(crate) fn validate_private_directory(fd: &OwnedFd) -> io::Result<()> {
    let stat = fstat(fd)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(io::Error::other("insecure private directory"));
    }
    Ok(())
}
