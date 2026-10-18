use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use super::super::super::CliError;

pub(super) fn validate(runtime_root: &Path, project_root: &Path) -> Result<(), CliError> {
    if !runtime_root.is_absolute()
        || !project_root.is_absolute()
        || runtime_root.parent() != project_root.parent()
        || runtime_root.file_name().is_none()
        || project_root.file_name().is_none()
        || runtime_root == project_root
        || reserved_name(runtime_root)
        || reserved_name(project_root)
    {
        return Err(CliError::Usage);
    }
    match fs::symlink_metadata(runtime_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(CliError::Usage),
    }
    match fs::symlink_metadata(project_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(CliError::Usage),
    }
}

fn reserved_name(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == "updates" || name == ".runne-native-enrollment")
}

pub(super) fn create_private_empty_project_root(path: &Path) -> Result<(), CliError> {
    create_private_empty_root(path)
}

pub(super) fn create_private_empty_runtime_root(path: &Path) -> Result<(), CliError> {
    create_private_empty_root(path)
}

fn create_private_empty_root(path: &Path) -> Result<(), CliError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|_| CliError::Runtime)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| CliError::Runtime)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| CliError::Runtime)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
        || !is_empty_directory(path)?
    {
        return Err(CliError::Runtime);
    }
    Ok(())
}

pub(super) fn is_empty_directory(path: &Path) -> Result<bool, CliError> {
    fs::read_dir(path)
        .map(|mut entries| entries.next().is_none())
        .map_err(|_| CliError::Runtime)
}
