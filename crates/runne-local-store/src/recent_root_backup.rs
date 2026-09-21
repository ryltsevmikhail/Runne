use super::recent_root_backup_compare::v4_tables_equal;
use super::recent_root_backup_failpoint::{AFTER_SNAPSHOT, hit};
use super::recent_root_backup_files::{
    artifact_exists, create_private_temporary, empty_private_temporary, promote_temporary,
    secure_and_sync, sync_file,
};
#[cfg(unix)]
use super::recent_root_backup_identity::sync_parent_directory;
use super::recent_root_backup_identity::{FileIdentity, file_identity};
use super::recent_root_schema::validate_v4_projects;
use super::{
    Connection, LocalStore, Path, PathBuf, StoreOpenError, backup_sidecars_absent, backup_uri,
    params, pre_v5_migration_backup_path, verify_pre_v5_backup_path,
};

/// Capability produced only after the backup was admitted against the current v4 source.
pub struct VerifiedPreV5Backup {
    path: PathBuf,
    source_identity: FileIdentity,
    backup_identity: FileIdentity,
}

impl LocalStore {
    pub(super) fn ensure_pre_v5_migration_backup(
        &self,
    ) -> Result<VerifiedPreV5Backup, StoreOpenError> {
        validate_source(&self.connection)?;
        let database_path = self.database_path()?;
        let source_identity = file_identity(&database_path)?;
        let final_path = pre_v5_migration_backup_path(&database_path)?;
        let temporary = final_path.with_extension("sqlite3.tmp");
        let final_exists = artifact_exists(&final_path)?;
        let temporary_exists = artifact_exists(&temporary)?;
        if final_exists && temporary_exists {
            if promoted_pair_is_resumable(
                &self.connection,
                &source_identity,
                &temporary,
                &final_path,
            )? {
                std::fs::remove_file(&temporary)
                    .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)?;
                sync_file(&final_path, file_identity(&final_path)?)?;
                #[cfg(unix)]
                sync_parent_directory(&final_path)?;
                return verified_source_backup(&self.connection, source_identity, final_path);
            }
            return Err(StoreOpenError::PreV5BackupConflict);
        }
        if final_exists {
            return verified_source_backup(&self.connection, source_identity, final_path);
        }
        if temporary_exists {
            if let Ok(temporary_identity) = empty_private_temporary(&temporary) {
                if temporary_identity == source_identity {
                    return Err(StoreOpenError::PreV5BackupConflict);
                }
                return self.fill_pre_v5_temporary(
                    source_identity,
                    temporary_identity,
                    &temporary,
                    &final_path,
                );
            }
            if file_identity(&temporary)?.links() != 1 {
                return Err(StoreOpenError::PreV5BackupConflict);
            }
            verify_temporary_source(&self.connection, source_identity, &temporary)
                .map_err(temp_recovery_error)?;
            promote_temporary(&temporary, &final_path)?;
            return verified_source_backup(&self.connection, source_identity, final_path);
        }
        self.create_pre_v5_backup(source_identity, &temporary, &final_path)
    }

    fn database_path(&self) -> Result<PathBuf, StoreOpenError> {
        self.connection
            .path()
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .ok_or(StoreOpenError::PreV5BackupRecoveryRequired)
    }

    fn create_pre_v5_backup(
        &self,
        source_identity: FileIdentity,
        temporary: &Path,
        final_path: &Path,
    ) -> Result<VerifiedPreV5Backup, StoreOpenError> {
        let temporary_identity = create_private_temporary(temporary)?;
        if temporary_identity == source_identity {
            return Err(StoreOpenError::PreV5BackupConflict);
        }
        self.fill_pre_v5_temporary(source_identity, temporary_identity, temporary, final_path)
    }

    fn fill_pre_v5_temporary(
        &self,
        source_identity: FileIdentity,
        temporary_identity: FileIdentity,
        temporary: &Path,
        final_path: &Path,
    ) -> Result<VerifiedPreV5Backup, StoreOpenError> {
        let temporary_text = temporary
            .to_str()
            .ok_or(StoreOpenError::PreV5BackupRecoveryRequired)?;
        self.connection
            .execute("VACUUM main INTO ?1", params![temporary_text])
            .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)?;
        hit(AFTER_SNAPSHOT)?;
        if file_identity(temporary)? != temporary_identity || temporary_identity.links() != 1 {
            return Err(StoreOpenError::PreV5BackupConflict);
        }
        secure_and_sync(temporary, temporary_identity)?;
        verify_temporary_source(&self.connection, source_identity, temporary)?;
        promote_temporary(temporary, final_path)?;
        verified_source_backup(&self.connection, source_identity, final_path.to_path_buf())
    }
}

pub fn validate_source(connection: &Connection) -> Result<(), StoreOpenError> {
    validate_v4_projects(connection).map_err(|_| StoreOpenError::PreV5BackupSourceMismatch)
}

fn verify_temporary_source(
    connection: &Connection,
    source: FileIdentity,
    path: &Path,
) -> Result<(), StoreOpenError> {
    if file_identity(path)? == source {
        return Err(StoreOpenError::PreV5BackupConflict);
    }
    verify_artifact(path)?;
    if !v4_tables_equal_to_path(connection, path)? {
        return Err(StoreOpenError::PreV5BackupSourceMismatch);
    }
    Ok(())
}

fn verified_source_backup(
    connection: &Connection,
    source_identity: FileIdentity,
    path: PathBuf,
) -> Result<VerifiedPreV5Backup, StoreOpenError> {
    verify_temporary_source(connection, source_identity, &path)?;
    let backup_identity = file_identity(&path)?;
    if backup_identity.links() != 1 {
        return Err(StoreOpenError::PreV5BackupConflict);
    }
    Ok(VerifiedPreV5Backup {
        path,
        source_identity,
        backup_identity,
    })
}

fn verify_artifact(path: &Path) -> Result<(), StoreOpenError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| StoreOpenError::PreV5BackupInvalid)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || !backup_sidecars_absent(path).map_err(|_| StoreOpenError::PreV5BackupInvalid)?
    {
        return Err(StoreOpenError::PreV5BackupInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreOpenError::PreV5BackupInvalid);
        }
    }
    verify_pre_v5_backup_path(path)
        .map(|_| ())
        .map_err(|_| StoreOpenError::PreV5BackupInvalid)
}

fn temp_recovery_error(error: StoreOpenError) -> StoreOpenError {
    match error {
        StoreOpenError::PreV5BackupInvalid => StoreOpenError::PreV5BackupRecoveryRequired,
        other => other,
    }
}

fn promoted_pair_is_resumable(
    connection: &Connection,
    source: &FileIdentity,
    temporary: &Path,
    final_path: &Path,
) -> Result<bool, StoreOpenError> {
    let temporary_identity = file_identity(temporary)?;
    let final_identity = file_identity(final_path)?;
    if temporary_identity != final_identity
        || temporary_identity == *source
        || temporary_identity.links() != 2
    {
        return Ok(false);
    }
    verify_temporary_source(connection, *source, temporary)?;
    verify_temporary_source(connection, *source, final_path)?;
    Ok(true)
}

pub fn attach_verified_backup(
    connection: &Connection,
    backup: VerifiedPreV5Backup,
) -> Result<(), StoreOpenError> {
    let VerifiedPreV5Backup {
        path,
        source_identity,
        backup_identity,
    } = backup;
    let source = connection
        .path()
        .map(PathBuf::from)
        .ok_or(StoreOpenError::PreV5BackupConflict)?;
    let current_backup = file_identity(&path)?;
    if file_identity(&source)? != source_identity
        || current_backup != backup_identity
        || current_backup.links() != 1
    {
        return Err(StoreOpenError::PreV5BackupConflict);
    }
    verify_artifact(&path)?;
    connection
        .execute("ATTACH DATABASE ?1 AS pre_v5_backup", [backup_uri(&path)?])
        .map(|_| ())
        .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)
}

fn v4_tables_equal_to_path(connection: &Connection, path: &Path) -> Result<bool, StoreOpenError> {
    connection
        .execute("ATTACH DATABASE ?1 AS pre_v5_backup", [backup_uri(path)?])
        .map_err(|_| StoreOpenError::PreV5BackupInvalid)?;
    let result = v4_tables_equal(connection);
    let detach = connection
        .execute_batch("DETACH DATABASE pre_v5_backup")
        .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired);
    detach?;
    result.map_err(|_| StoreOpenError::PreV5BackupSourceMismatch)
}
