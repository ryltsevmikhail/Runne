use super::*;

impl StoreTransaction {
    /// Open a database at `db_path`, apply migrations, run startup gates.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The database cannot be opened
    /// - PRAGMA setup fails
    /// - Migrations fail
    /// - Startup integrity checks fail
    pub fn open(
        db_path: &str,
        runtime_authority_id: RuntimeAuthorityId,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
    ) -> Result<Self, CommitError> {
        let writer = open_with_pragmas(db_path).map_err(|_| {
            CommitError::StorageFailure(gocode_application::ports::StorageFailureKind::Unavailable)
        })?;

        apply_migrations(&writer).map_err(|_| {
            CommitError::StorageFailure(gocode_application::ports::StorageFailureKind::CorruptData)
        })?;

        run_startup_gates(&writer, db_path).map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        // The opened writer owns lifecycle classification. A read-only
        // connection cannot mutate WAL state and deliberately avoids a second
        // preflight/classification pass.
        let reader = if db_path == ":memory:" {
            Connection::open_in_memory()
        } else {
            Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        }
        .map_err(|_| {
            CommitError::StorageFailure(gocode_application::ports::StorageFailureKind::Unavailable)
        })?;

        Ok(Self::from_connections(
            writer,
            reader,
            runtime_authority_id,
            prohibited_content,
        ))
    }

    /// Adopts validated writer and reader connections without reopening their paths.
    ///
    /// The caller owns path admission. Migrations and startup gates still run on
    /// the supplied writer before the store becomes available.
    pub fn open_with_connections(
        db_path: &str,
        writer: Connection,
        reader: Connection,
        runtime_authority_id: RuntimeAuthorityId,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
    ) -> Result<Self, CommitError> {
        apply_migrations(&writer).map_err(|_| {
            CommitError::StorageFailure(gocode_application::ports::StorageFailureKind::CorruptData)
        })?;
        run_startup_gates(&writer, db_path).map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        Ok(Self::from_connections(
            writer,
            reader,
            runtime_authority_id,
            prohibited_content,
        ))
    }

    fn from_connections(
        writer: Connection,
        reader: Connection,
        runtime_authority_id: RuntimeAuthorityId,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
    ) -> Self {
        Self {
            inner: Arc::new(StoreInner {
                writer: Mutex::new(writer),
                reader: Mutex::new(reader),
                id_counter: AtomicU64::new(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                ),
            }),
            runtime_authority_id,
            prohibited_content,
        }
    }

    /// Return the runtime authority ID.
    pub fn runtime_authority_id(&self) -> &RuntimeAuthorityId {
        &self.runtime_authority_id
    }

    /// Runs one Project/Workspace mutation under the authoritative writer lock.
    ///
    /// Sharing this exact `BEGIN IMMEDIATE` boundary with TaskRun commits is the
    /// deletion fence; Project/Workspace adapters must not open another writer.
    pub(crate) fn with_project_workspace_transaction<T>(
        &self,
        operation: impl FnOnce(
            &rusqlite::Transaction<'_>,
        )
            -> Result<T, gocode_application::ports::ProjectWorkspaceRepositoryError>,
    ) -> Result<T, gocode_application::ports::ProjectWorkspaceRepositoryError> {
        use gocode_application::ports::ProjectWorkspaceRepositoryError as Error;

        let mut connection = self.inner.writer.lock().map_err(|_| Error::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        let result = operation(&transaction)?;
        transaction.commit().map_err(|_| Error::Unavailable)?;
        Ok(result)
    }

    /// Runs a Project/Workspace query against the authoritative connection.
    pub(crate) fn with_project_workspace_reader<T>(
        &self,
        operation: impl FnOnce(
            &rusqlite::Connection,
        )
            -> Result<T, gocode_application::ports::ProjectWorkspaceRepositoryError>,
    ) -> Result<T, gocode_application::ports::ProjectWorkspaceRepositoryError> {
        use gocode_application::ports::ProjectWorkspaceRepositoryError as Error;

        let connection = self.inner.reader.lock().map_err(|_| Error::Unavailable)?;
        operation(&connection)
    }

    /// Generate a UUIDv7 byte array from the monotonic counter.
    pub(super) fn generate_uuid(&self) -> [u8; 16] {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let counter = self.inner.id_counter.fetch_add(1, Ordering::SeqCst);

        let mut bytes = [0u8; 16];
        bytes[0..6].copy_from_slice(&ts.to_be_bytes()[2..8]);
        bytes[6] = 0x70 | (bytes[6] & 0x0F);
        bytes[8] = 0x80 | (bytes[8] & 0x3F);
        bytes[10..16].copy_from_slice(&counter.to_be_bytes()[2..8]);

        bytes
    }
}

// ── EventStore impl ──────────────────────────────────────────────────────
