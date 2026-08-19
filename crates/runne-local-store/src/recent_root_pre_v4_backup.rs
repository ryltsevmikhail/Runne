use super::recent_root_backup_failpoint::{AFTER_SNAPSHOT, hit};
use super::recent_root_backup_files::{
    artifact_exists, create_private_temporary, empty_private_temporary, promote_temporary,
    secure_and_sync, sync_file,
};
use super::recent_root_backup_identity::{FileIdentity, file_identity, sync_parent_directory};
use super::{
    Connection, LocalStore, Path, PathBuf, StoreOpenError, backup_uri, params,
    verify_pre_v4_backup_path,
};
use rusqlite::types::ValueRef;

const V3_TABLES: &[&str] = &[
    "settings",
    "projects",
    "meta",
    "drafts",
    "projections",
    "event_journal",
    "replay_cursors",
    "mutation_ledger",
    "window_layout",
];

impl LocalStore {
    pub(super) fn ensure_pre_v4_migration_backup(&self) -> Result<(), StoreOpenError> {
        let Some(path) = self
            .connection
            .path()
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
        else {
            return Ok(());
        };
        let source = file_identity(&path).map_err(unavailable)?;
        let final_path = super::pre_v4_migration_backup_path(&path)?;
        let temporary = final_path.with_extension("sqlite3.tmp");
        match (artifact_exists(&final_path), artifact_exists(&temporary)) {
            (Ok(true), Ok(true)) => self.resume_pair(source, &temporary, &final_path),
            (Ok(true), Ok(false)) => verify_source(&self.connection, source, &final_path),
            (Ok(false), Ok(true)) => self.resume_temporary(source, &temporary, &final_path),
            (Ok(false), Ok(false)) => self.create_backup(source, &temporary, &final_path),
            _ => Err(StoreOpenError::MigrationBackupUnavailable),
        }
    }

    fn create_backup(
        &self,
        source: FileIdentity,
        temporary: &Path,
        final_path: &Path,
    ) -> Result<(), StoreOpenError> {
        let identity = create_private_temporary(temporary).map_err(unavailable)?;
        self.fill_temporary(source, identity, temporary, final_path)
    }

    fn resume_temporary(
        &self,
        source: FileIdentity,
        temporary: &Path,
        final_path: &Path,
    ) -> Result<(), StoreOpenError> {
        if let Ok(identity) = empty_private_temporary(temporary) {
            return self.fill_temporary(source, identity, temporary, final_path);
        }
        verify_source(&self.connection, source, temporary)?;
        promote_temporary(temporary, final_path).map_err(unavailable)?;
        verify_source(&self.connection, source, final_path)
    }

    fn fill_temporary(
        &self,
        source: FileIdentity,
        identity: FileIdentity,
        temporary: &Path,
        final_path: &Path,
    ) -> Result<(), StoreOpenError> {
        if identity == source || identity.links() != 1 {
            return Err(StoreOpenError::MigrationBackupUnavailable);
        }
        let path = temporary
            .to_str()
            .ok_or(StoreOpenError::MigrationBackupUnavailable)?;
        self.connection
            .execute("VACUUM main INTO ?1", params![path])
            .map_err(unavailable)?;
        hit(AFTER_SNAPSHOT).map_err(unavailable)?;
        if file_identity(temporary).map_err(unavailable)? != identity {
            return Err(StoreOpenError::MigrationBackupUnavailable);
        }
        secure_and_sync(temporary, identity).map_err(unavailable)?;
        verify_source(&self.connection, source, temporary)?;
        promote_temporary(temporary, final_path).map_err(unavailable)?;
        verify_source(&self.connection, source, final_path)
    }

    fn resume_pair(
        &self,
        source: FileIdentity,
        temporary: &Path,
        final_path: &Path,
    ) -> Result<(), StoreOpenError> {
        let temp = file_identity(temporary).map_err(unavailable)?;
        if temp != file_identity(final_path).map_err(unavailable)?
            || temp == source
            || temp.links() != 2
        {
            return Err(StoreOpenError::MigrationBackupUnavailable);
        }
        verify_content(&self.connection, temporary)?;
        verify_content(&self.connection, final_path)?;
        std::fs::remove_file(temporary).map_err(unavailable)?;
        sync_file(final_path, temp).map_err(unavailable)?;
        #[cfg(unix)]
        sync_parent_directory(final_path).map_err(unavailable)?;
        verify_source(&self.connection, source, final_path)
    }
}

fn verify_source(
    connection: &Connection,
    source: FileIdentity,
    path: &Path,
) -> Result<(), StoreOpenError> {
    let identity = file_identity(path).map_err(unavailable)?;
    if identity == source || identity.links() != 1 {
        return Err(StoreOpenError::MigrationBackupUnavailable);
    }
    verify_content(connection, path)
}

fn verify_content(connection: &Connection, path: &Path) -> Result<(), StoreOpenError> {
    verify_pre_v4_backup_path(path).map_err(unavailable)?;
    attach_and_compare(connection, path)
}

fn attach_and_compare(connection: &Connection, path: &Path) -> Result<(), StoreOpenError> {
    connection
        .execute(
            "ATTACH DATABASE ?1 AS pre_v4_backup",
            [backup_uri(path).map_err(unavailable)?],
        )
        .map_err(unavailable)?;
    let result = tables_equal(connection);
    let detach = connection
        .execute_batch("DETACH DATABASE pre_v4_backup")
        .map_err(unavailable);
    detach?;
    result
}

fn tables_equal(connection: &Connection) -> Result<(), StoreOpenError> {
    for table in V3_TABLES {
        let query = format!("SELECT * FROM {{schema}}.\"{table}\" ORDER BY rowid");
        let mut main = connection
            .prepare(&query.replace("{schema}", "main"))
            .map_err(unavailable)?;
        let mut backup = connection
            .prepare(&query.replace("{schema}", "pre_v4_backup"))
            .map_err(unavailable)?;
        let mut main_rows = main.query([]).map_err(unavailable)?;
        let mut backup_rows = backup.query([]).map_err(unavailable)?;
        loop {
            match (
                main_rows.next().map_err(unavailable)?,
                backup_rows.next().map_err(unavailable)?,
            ) {
                (None, None) => break,
                (Some(left), Some(right))
                    if encode_row(left).map_err(unavailable)?
                        == encode_row(right).map_err(unavailable)? => {}
                _ => return Err(StoreOpenError::MigrationBackupUnavailable),
            }
        }
    }
    Ok(())
}

fn encode_row(row: &rusqlite::Row<'_>) -> Result<Vec<u8>, rusqlite::Error> {
    let mut output = Vec::new();
    for column in 0..row.as_ref().column_count() {
        encode(&mut output, row.get_ref(column)?);
    }
    Ok(output)
}

fn encode(output: &mut Vec<u8>, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => output.push(b'n'),
        ValueRef::Integer(value) => {
            output.push(b'i');
            output.extend(value.to_be_bytes());
        }
        ValueRef::Real(value) => {
            output.push(b'r');
            output.extend(value.to_bits().to_be_bytes());
        }
        ValueRef::Text(value) => bytes(output, b't', value),
        ValueRef::Blob(value) => bytes(output, b'b', value),
    }
}

fn bytes(output: &mut Vec<u8>, tag: u8, value: &[u8]) {
    output.push(tag);
    output.extend(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend(value);
}

fn unavailable<T>(_: T) -> StoreOpenError {
    StoreOpenError::MigrationBackupUnavailable
}
