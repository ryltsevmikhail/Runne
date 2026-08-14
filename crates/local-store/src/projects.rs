use super::{
    LocalProject, LocalStore, LocalStoreDiagnostics, OptionalExtension, Path, PathBuf,
    ProjectOpenError, SecurityTransactionError, SystemTime, UNIX_EPOCH, params,
};

impl LocalStore {
    /// Stores one local setting and advances its revision atomically.
    ///
    /// # Errors
    ///
    /// Returns the underlying `SQLite` error when the setting transaction cannot
    /// be committed.
    pub fn set_setting(&mut self, key: &str, value: &str) -> rusqlite::Result<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "
            INSERT INTO settings (key, value)
            VALUES (?1, ?2)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                revision = settings.revision + 1
            ",
            params![key, value],
        )?;
        transaction.commit()
    }

    /// Reads a non-secret string setting.
    ///
    /// # Errors
    ///
    /// Returns an error if the query cannot be completed.
    pub fn get_setting(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
    }

    /// Persists a validated local directory and returns its stable project row.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory is invalid, cannot be resolved, or
    /// the storage transaction cannot be committed.
    pub fn open_local_project(&mut self, path: &Path) -> Result<LocalProject, ProjectOpenError> {
        if !path.is_dir() {
            return Err(ProjectOpenError::NotDirectory);
        }
        let path = path
            .canonicalize()
            .map_err(ProjectOpenError::PathUnavailable)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or(ProjectOpenError::InvalidName)?
            .to_owned();
        let last_opened_at = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ProjectOpenError::InvalidClock)?
                .as_millis(),
        )
        .map_err(|_| ProjectOpenError::InvalidClock)?;
        let path_value = path.to_string_lossy();
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "
            INSERT INTO recent_roots (
                project_id, workspace_id, display_name, last_opened_at,
                root_state, native_root_metadata, legacy_project_id
            ) VALUES (
                NULL, NULL, ?1, ?2, 'migration_required', ?3,
                (SELECT COALESCE(MAX(legacy_project_id), 0) + 1 FROM recent_roots)
            )
            ON CONFLICT DO NOTHING
            ",
            params![name, last_opened_at, path_value],
        )?;
        let id = transaction.query_row(
            "
            SELECT legacy_project_id
            FROM recent_roots
            WHERE root_state = 'migration_required' AND native_root_metadata = ?1
            ORDER BY legacy_project_id DESC
            LIMIT 1
            ",
            params![path_value],
            |row| row.get(0),
        )?;
        transaction.execute(
            "
            UPDATE recent_roots
            SET display_name = ?1, last_opened_at = ?2
            WHERE legacy_project_id = ?3
            ",
            params![name, last_opened_at, id],
        )?;
        transaction.commit()?;
        Ok(LocalProject {
            id,
            name,
            path,
            last_opened_at,
        })
    }

    /// Lists local projects with the most recently opened first.
    ///
    /// # Errors
    ///
    /// Returns an error if the query or stored row cannot be read.
    pub fn list_projects(&self) -> rusqlite::Result<Vec<LocalProject>> {
        let mut statement = self.connection.prepare(
            "
            SELECT legacy_project_id, display_name, native_root_metadata, last_opened_at
            FROM recent_roots
            WHERE root_state = 'migration_required'
            ORDER BY last_opened_at DESC, legacy_project_id DESC
            ",
        )?;
        statement
            .query_map([], |row| {
                Ok(LocalProject {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    path: PathBuf::from(row.get::<_, String>(2)?),
                    last_opened_at: row.get(3)?,
                })
            })?
            .collect()
    }

    /// Loads one local project by stable database id.
    ///
    /// # Errors
    ///
    /// Returns an error if the query or stored row cannot be read.
    pub fn get_project(&self, id: i64) -> rusqlite::Result<Option<LocalProject>> {
        self.connection
            .query_row(
                "
                SELECT legacy_project_id, display_name, native_root_metadata, last_opened_at
                FROM recent_roots
                WHERE root_state = 'migration_required' AND legacy_project_id = ?1
                ",
                params![id],
                |row| {
                    Ok(LocalProject {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        path: PathBuf::from(row.get::<_, String>(2)?),
                        last_opened_at: row.get(3)?,
                    })
                },
            )
            .optional()
    }

    /// Returns bounded, path-free local storage diagnostics.
    ///
    /// # Errors
    ///
    /// Returns an error if metadata or counts cannot be read.
    pub fn diagnostics(&self) -> Result<LocalStoreDiagnostics, SecurityTransactionError> {
        let (schema_version, database_generation): (i64, i64) = self.connection.query_row(
            "
            SELECT schema_version, db_generation
            FROM meta
            WHERE singleton = 1
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let project_count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM recent_roots", [], |row| row.get(0))?;
        Ok(LocalStoreDiagnostics {
            schema_version: u32::try_from(schema_version)
                .map_err(|_| SecurityTransactionError::GenerationOutOfRange)?,
            database_generation: u64::try_from(database_generation)
                .map_err(|_| SecurityTransactionError::GenerationOutOfRange)?,
            project_count: u64::try_from(project_count)
                .map_err(|_| SecurityTransactionError::GenerationOutOfRange)?,
        })
    }
}
