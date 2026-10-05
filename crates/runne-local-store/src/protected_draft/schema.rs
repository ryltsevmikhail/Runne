#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::{fs::OpenOptions, path::PathBuf};

use rusqlite::{Connection, OpenFlags, TransactionBehavior};

use super::types::ProtectedDraftError;

const DRAFTS_SCHEMA_VERSION: i64 = 2;
const DRAFTS_SCHEMA: &str = "CREATE TABLE protected_drafts (lineage TEXT NOT NULL, authority TEXT NOT NULL, principal TEXT NOT NULL, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision >= 1), deleted INTEGER NOT NULL CHECK(deleted IN (0,1)), payload BLOB NOT NULL, PRIMARY KEY(lineage,authority,principal,project_id,workspace_id)) STRICT";
type SchemaObject = (String, String, String, Option<String>);

pub(super) fn ensure_schema(connection: &mut Connection) -> Result<(), ProtectedDraftError> {
    connection
        .execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;",
        )
        .map_err(|_| ProtectedDraftError::Storage)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ProtectedDraftError::Storage)?;
    let version: i64 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| ProtectedDraftError::Storage)?;
    let objects = schema_objects(&transaction)?;
    if version == 0 && objects.is_empty() {
        transaction
            .execute_batch(DRAFTS_SCHEMA)
            .map_err(|_| ProtectedDraftError::Storage)?;
        transaction
            .pragma_update(None, "user_version", DRAFTS_SCHEMA_VERSION)
            .map_err(|_| ProtectedDraftError::Storage)?;
        validate_schema_objects(&transaction)?;
        transaction
            .commit()
            .map_err(|_| ProtectedDraftError::Storage)?;
        return Ok(());
    }
    if version != DRAFTS_SCHEMA_VERSION {
        return Err(ProtectedDraftError::Invalid);
    }
    validate_schema_objects(&transaction)?;
    transaction
        .commit()
        .map_err(|_| ProtectedDraftError::Storage)
}

fn validate_schema_objects(connection: &Connection) -> Result<(), ProtectedDraftError> {
    let objects = schema_objects(connection)?;
    let exact_table = objects.iter().any(|(kind, name, table, sql)| {
        kind == "table"
            && name == "protected_drafts"
            && table == "protected_drafts"
            && sql.as_deref() == Some(DRAFTS_SCHEMA)
    });
    let exact_primary_key = objects.iter().any(|(kind, name, table, sql)| {
        kind == "index"
            && name == "sqlite_autoindex_protected_drafts_1"
            && table == "protected_drafts"
            && sql.is_none()
    });
    if objects.len() != 2 || !exact_table || !exact_primary_key {
        return Err(ProtectedDraftError::Invalid);
    }
    Ok(())
}

fn schema_objects(connection: &Connection) -> Result<Vec<SchemaObject>, ProtectedDraftError> {
    connection
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })?
                .collect()
        })
        .map_err(|_| ProtectedDraftError::Storage)
}

pub(super) fn open_database(
    profile_path: &std::path::Path,
) -> Result<Connection, ProtectedDraftError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = profile_path;
        Err(ProtectedDraftError::Unavailable)
    }
    #[cfg(target_os = "linux")]
    {
        open_linux_database(profile_path)
    }
}

#[cfg(target_os = "linux")]
fn open_linux_database(profile_path: &std::path::Path) -> Result<Connection, ProtectedDraftError> {
    let parent = profile_path
        .parent()
        .ok_or(ProtectedDraftError::Unavailable)?;
    let before = std::fs::symlink_metadata(parent).map_err(|_| ProtectedDraftError::Unavailable)?;
    let uid = nix::unistd::geteuid().as_raw();
    if !before.is_dir()
        || before.file_type().is_symlink()
        || before.uid() != uid
        || before.permissions().mode() & 0o022 != 0
    {
        return Err(ProtectedDraftError::Unavailable);
    }
    let path = sidecar_path(profile_path);
    validate_auxiliaries(&path, uid)?;
    ensure_sidecar_file(&path, parent, uid)?;
    validate_sidecar_file(&path, uid)?;
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| ProtectedDraftError::Unavailable)?;
    validate_opened_file(&connection, &path, uid, &before)?;
    validate_auxiliaries(&path, uid)?;
    Ok(connection)
}

#[cfg(target_os = "linux")]
fn sidecar_path(profile_path: &std::path::Path) -> PathBuf {
    let mut path = PathBuf::from(profile_path.as_os_str());
    path.as_mut_os_string().push(".drafts.sqlite3");
    path
}

#[cfg(target_os = "linux")]
fn ensure_sidecar_file(
    path: &std::path::Path,
    parent: &std::path::Path,
    uid: u32,
) -> Result<(), ProtectedDraftError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true).mode(0o600);
            match options.open(path) {
                Ok(file) => {
                    file.sync_all()
                        .map_err(|_| ProtectedDraftError::Unavailable)?;
                    OpenOptions::new()
                        .read(true)
                        .open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|_| ProtectedDraftError::Unavailable)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(ProtectedDraftError::Unavailable),
            }
            validate_sidecar_file(path, uid)
        }
        Err(_) => Err(ProtectedDraftError::Unavailable),
    }
}

#[cfg(target_os = "linux")]
fn validate_sidecar_file(path: &std::path::Path, uid: u32) -> Result<(), ProtectedDraftError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ProtectedDraftError::Unavailable)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ProtectedDraftError::Unavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_opened_file(
    connection: &Connection,
    path: &std::path::Path,
    uid: u32,
    parent_before: &std::fs::Metadata,
) -> Result<(), ProtectedDraftError> {
    let opened = runne_sqlite_native_identity::opened_database_identity(connection)
        .map_err(|_| ProtectedDraftError::Unavailable)?;
    let named = runne_sqlite_native_identity::path_database_identity(path)
        .map_err(|_| ProtectedDraftError::Unavailable)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ProtectedDraftError::Unavailable)?;
    let parent = path.parent().ok_or(ProtectedDraftError::Unavailable)?;
    let after = std::fs::symlink_metadata(parent).map_err(|_| ProtectedDraftError::Unavailable)?;
    if opened != named
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || after.dev() != parent_before.dev()
        || after.ino() != parent_before.ino()
        || after.uid() != uid
    {
        return Err(ProtectedDraftError::Unavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_auxiliaries(path: &std::path::Path, uid: u32) -> Result<(), ProtectedDraftError> {
    validate_auxiliary(path, "-journal", uid, true)?;
    validate_auxiliary(path, "-wal", uid, false)?;
    validate_auxiliary(path, "-shm", uid, false)
}

#[cfg(target_os = "linux")]
fn validate_auxiliary(
    path: &std::path::Path,
    suffix: &str,
    uid: u32,
    allow_recovery_journal: bool,
) -> Result<(), ProtectedDraftError> {
    let mut auxiliary = PathBuf::from(path.as_os_str());
    auxiliary.as_mut_os_string().push(suffix);
    match std::fs::symlink_metadata(&auxiliary) {
        Ok(metadata)
            if allow_recovery_journal
                && metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == uid
                && metadata.permissions().mode() & 0o777 == 0o600
                && metadata.nlink() == 1 =>
        {
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(ProtectedDraftError::Unavailable),
    }
}

pub(super) fn map_write_error(error: &rusqlite::Error) -> ProtectedDraftError {
    if matches!(error, rusqlite::Error::SqliteFailure(failure, _) if failure.code == rusqlite::ErrorCode::ConstraintViolation)
    {
        ProtectedDraftError::Conflict
    } else {
        ProtectedDraftError::Storage
    }
}
