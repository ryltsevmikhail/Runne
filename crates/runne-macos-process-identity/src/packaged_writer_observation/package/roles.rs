use std::path::{Path, PathBuf};

use super::super::super::MacOsPackagedWriterObservationError;

pub(super) const DESKTOP: &[&str] = &["Contents", "MacOS", "runne-desktop"];
pub(super) const WRITER: &[&str] = &["Contents", "MacOS", "runne"];
pub(super) const DAEMON: &[&str] = &["Contents", "MacOS", "runned"];
pub(super) const CONTRACT: &[&str] = &[
    "Contents",
    "Resources",
    "contracts",
    "gocode-ui-client-2",
    "bundle.json",
];

#[derive(Clone, Copy)]
pub(in crate::packaged_writer_observation) enum PackageRole {
    Writer,
    Daemon,
}

pub(super) fn fixed_application_from_writer(
    writer: &Path,
) -> Result<PathBuf, MacOsPackagedWriterObservationError> {
    let macos = writer
        .parent()
        .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
    let contents = macos
        .parent()
        .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
    let application = contents
        .parent()
        .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
    (writer.is_absolute()
        && writer.file_name().is_some_and(|name| name == "runne")
        && macos.file_name().is_some_and(|name| name == "MacOS")
        && contents.file_name().is_some_and(|name| name == "Contents")
        && application
            .file_name()
            .is_some_and(|name| name == "Runne.app"))
    .then(|| application.to_path_buf())
    .ok_or(MacOsPackagedWriterObservationError::Rejected)
}

#[cfg(test)]
pub(crate) fn test_only_is_fixed_writer_locator(writer: &Path) -> bool {
    fixed_application_from_writer(writer).is_ok()
}
