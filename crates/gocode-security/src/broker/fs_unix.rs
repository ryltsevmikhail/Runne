use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags, fstat, open, openat};

use super::fs::FsBrokerError;

pub(super) struct UnixResolution {
    pub path: PathBuf,
    pub file_fd: OwnedFd,
}

pub(super) fn resolve_nofollow(
    root: &Path,
    components: &[String],
    final_flags: OFlags,
) -> Result<UnixResolution, FsBrokerError> {
    let mut directory = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(map_open_error)?;
    let root_device = fstat(&directory)
        .map_err(|error| FsBrokerError::Io(error.to_string()))?
        .st_dev;
    let mut resolved_component = false;

    for (index, component) in components.iter().enumerate() {
        let is_last = index + 1 == components.len();
        let mut flags = OFlags::CLOEXEC | OFlags::NOFOLLOW;
        if !is_last {
            flags |= OFlags::RDONLY | OFlags::DIRECTORY;
        } else {
            flags |= final_flags;
        }
        let opened =
            openat(&directory, component.as_str(), flags, Mode::empty()).map_err(map_open_error)?;
        let stat = fstat(&opened).map_err(|error| FsBrokerError::Io(error.to_string()))?;
        if stat.st_dev != root_device {
            return Err(FsBrokerError::PathEscapesRoot);
        }
        resolved_component = true;
        directory = opened;
    }

    if !resolved_component {
        return Err(FsBrokerError::PathNotRelative);
    }
    Ok(UnixResolution {
        path: root.join(components.join("/")),
        file_fd: directory,
    })
}

pub(super) fn open_follow(path: &Path, flags: OFlags) -> Result<OwnedFd, FsBrokerError> {
    let fd = open(path, flags | OFlags::CLOEXEC, Mode::empty()).map_err(map_open_error)?;
    Ok(fd)
}

/// Классифицирует ошибки `open`/`openat` как boundary violations.
///
/// Linux: `openat(O_NOFOLLOW)` на symlink возвращает `ELOOP`.
/// `ENOTDIR` также возникает для обычного файла в промежуточном компоненте.
fn map_open_error(error: rustix::io::Errno) -> FsBrokerError {
    if error == rustix::io::Errno::LOOP {
        FsBrokerError::SymlinkEscapesRoot
    } else if error == rustix::io::Errno::NOTDIR {
        FsBrokerError::NotDirectory
    } else {
        FsBrokerError::Io(error.to_string())
    }
}
