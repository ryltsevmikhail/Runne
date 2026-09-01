use std::fs::File;
use std::path::{Component, Path};

use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;

use super::super::super::MacOsPackagedWriterObservationError;

pub(super) fn open_absolute_directory(
    path: &Path,
) -> Result<File, MacOsPackagedWriterObservationError> {
    let mut current = File::from(
        open("/", directory_flags(), Mode::empty())
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?,
    );
    let mut rooted = false;
    for component in path.components() {
        match component {
            Component::RootDir if !rooted => rooted = true,
            Component::Normal(name) if rooted => {
                current = File::from(
                    openat(&current, name, directory_flags(), Mode::empty())
                        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?,
                );
            }
            _ => return Err(MacOsPackagedWriterObservationError::Rejected),
        }
    }
    rooted
        .then_some(current)
        .ok_or(MacOsPackagedWriterObservationError::Rejected)
}

pub(super) fn open_absolute_file(path: &Path) -> Result<File, MacOsPackagedWriterObservationError> {
    let parent = path
        .parent()
        .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
    let name = path
        .file_name()
        .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
    let directory = open_absolute_directory(parent)?;
    openat(&directory, name, file_flags(), Mode::empty())
        .map(File::from)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)
}

pub(super) fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

pub(super) fn file_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}
