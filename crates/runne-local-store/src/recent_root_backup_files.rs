use super::recent_root_backup_failpoint::{
    AFTER_FILE_DURABLE, AFTER_PRIVATE_CREATE, AFTER_PUBLISH, AFTER_PUBLISH_DURABLE, hit,
};
#[cfg(not(windows))]
use super::recent_root_backup_identity::sync_parent_directory;
use super::recent_root_backup_identity::{FileIdentity, file_identity};
use super::{Path, StoreOpenError, backup_sidecars_absent};

pub fn artifact_exists(path: &Path) -> Result<bool, StoreOpenError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(StoreOpenError::PreV5BackupRecoveryRequired),
    }
}

pub fn create_private_temporary(path: &Path) -> Result<FileIdentity, StoreOpenError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)?;
    file.sync_all()
        .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)?;
    drop(file);
    let identity = file_identity(path)?;
    hit(AFTER_PRIVATE_CREATE)?;
    Ok(identity)
}

pub fn empty_private_temporary(path: &Path) -> Result<FileIdentity, StoreOpenError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != 0
        || !backup_sidecars_absent(path).map_err(|_| StoreOpenError::PreV5BackupConflict)?
    {
        return Err(StoreOpenError::PreV5BackupConflict);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreOpenError::PreV5BackupConflict);
        }
    }
    let identity = file_identity(path)?;
    if identity.links() != 1 {
        return Err(StoreOpenError::PreV5BackupConflict);
    }
    Ok(identity)
}

pub fn secure_and_sync(path: &Path, expected: FileIdentity) -> Result<(), StoreOpenError> {
    if file_identity(path)? != expected {
        return Err(StoreOpenError::PreV5BackupConflict);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)?;
    }
    sync_file(path, expected)?;
    hit(AFTER_FILE_DURABLE)
}

pub fn sync_file(path: &Path, expected: FileIdentity) -> Result<(), StoreOpenError> {
    #[cfg(not(windows))]
    let _ = expected;
    #[cfg(windows)]
    {
        runne_windows_native_handle::sync_regular_file(path, expected.native_id())
            .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)?;
        (file_identity(path)? == expected)
            .then_some(())
            .ok_or(StoreOpenError::PreV5BackupConflict)
    }
    #[cfg(not(windows))]
    {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)
    }
}

pub fn promote_temporary(temporary: &Path, final_path: &Path) -> Result<(), StoreOpenError> {
    if artifact_exists(final_path)? || file_identity(temporary)?.links() != 1 {
        return Err(StoreOpenError::PreV5BackupConflict);
    }
    let identity = file_identity(temporary)?;
    #[cfg(windows)]
    {
        runne_windows_native_handle::move_regular_file_no_replace_write_through(
            temporary,
            final_path,
            identity.native_id(),
        )
        .map_err(|error| match error {
            runne_windows_native_handle::NativeFileError::DestinationExists
            | runne_windows_native_handle::NativeFileError::Rejected => {
                StoreOpenError::PreV5BackupConflict
            }
            runne_windows_native_handle::NativeFileError::Unavailable => {
                StoreOpenError::PreV5BackupRecoveryRequired
            }
        })?;
        hit(AFTER_PUBLISH)?;
        sync_file(final_path, identity)?;
        hit(AFTER_PUBLISH_DURABLE)
    }
    #[cfg(not(windows))]
    {
        std::fs::hard_link(temporary, final_path)
            .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)?;
        hit(AFTER_PUBLISH)?;
        sync_file(final_path, identity)?;
        sync_parent_directory(final_path)?;
        hit(AFTER_PUBLISH_DURABLE)?;
        std::fs::remove_file(temporary).map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)?;
        sync_file(final_path, identity)?;
        sync_parent_directory(final_path)
    }
}
