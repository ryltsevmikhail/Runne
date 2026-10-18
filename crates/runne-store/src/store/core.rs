use super::*;
#[path = "execution_node.rs"]
mod execution_node;
mod permission_owner;
pub(super) use permission_owner::RegisteredPermissionOwnerPair;

impl StoreTransaction {
    /// Open a file-backed database at `db_path`, apply migrations, and run startup gates.
    ///
    /// `StoreTransaction` owns separate writer and reader connections, so it
    /// requires a file-backed SQLite path. The exact `:memory:` path is not
    /// supported by this public constructor.
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
        if db_path == ":memory:" {
            return Err(CommitError::StorageFailure(
                runne_application::ports::StorageFailureKind::Unavailable,
            ));
        }

        let writer =
            open_managed_connection(Path::new(db_path), ConnectionMode::Writer).map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::Unavailable,
                )
            })?;

        apply_migrations(&writer).map_err(|_| {
            CommitError::StorageFailure(runne_application::ports::StorageFailureKind::CorruptData)
        })?;

        let reader =
            open_managed_connection(Path::new(db_path), ConnectionMode::Reader).map_err(|_| {
                CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::Unavailable,
                )
            })?;

        Self::open_with_connections(
            db_path,
            writer,
            reader,
            runtime_authority_id,
            prohibited_content,
        )
    }

    /// Adopts validated writer and reader connections without reopening their paths.
    ///
    /// The caller owns path admission. Migrations and startup gates still run on
    /// the supplied writer before the store becomes available.
    pub fn open_with_connections(
        _db_path: &str,
        writer: ManagedConnection,
        reader: ManagedConnection,
        runtime_authority_id: RuntimeAuthorityId,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
    ) -> Result<Self, CommitError> {
        Self::open_with_optional_permission_owner(
            writer,
            reader,
            runtime_authority_id,
            prohibited_content,
            None,
        )
    }

    /// Adopts the canonical connections with one immutable T1/native/root owner bundle.
    #[cfg(target_os = "linux")]
    #[expect(
        clippy::too_many_arguments,
        reason = "this constructor receives the complete canonical connection and permission-owner bundle"
    )]
    pub fn open_with_connections_and_permission_owner(
        _db_path: &str,
        writer: ManagedConnection,
        reader: ManagedConnection,
        runtime_authority_id: RuntimeAuthorityId,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
        trust_store: Arc<crate::ProjectTrustStore>,
        native_owner: Arc<runne_platform::local_command_linux::LinuxPermissionOwnerV1>,
        root_fence: Arc<dyn super::taskrun_local_command::PermissionRootFenceOwnerV1>,
    ) -> Result<Self, CommitError> {
        let owner = RegisteredPermissionOwnerPair::checked(
            runtime_authority_id.clone(),
            trust_store,
            native_owner,
            root_fence,
        )?;
        Self::open_with_optional_permission_owner(
            writer,
            reader,
            runtime_authority_id,
            prohibited_content,
            Some(owner),
        )
    }

    fn open_with_optional_permission_owner(
        writer: ManagedConnection,
        reader: ManagedConnection,
        runtime_authority_id: RuntimeAuthorityId,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
        permission_owner: Option<RegisteredPermissionOwnerPair>,
    ) -> Result<Self, CommitError> {
        apply_migrations(&writer).map_err(|_| {
            CommitError::StorageFailure(runne_application::ports::StorageFailureKind::CorruptData)
        })?;
        readiness_from_managed(&writer).map_err(|_| {
            CommitError::StorageFailure(
                runne_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;
        readiness_from_managed(&reader).map_err(|_| {
            CommitError::StorageFailure(
                runne_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;
        publication_from_managed(&writer).map_err(|_| {
            CommitError::StorageFailure(
                runne_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;
        publication_from_managed(&reader).map_err(|_| {
            CommitError::StorageFailure(
                runne_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        Ok(Self::from_connections(
            writer,
            reader,
            runtime_authority_id,
            prohibited_content,
            permission_owner,
        ))
    }

    fn from_connections(
        writer: ManagedConnection,
        reader: ManagedConnection,
        runtime_authority_id: RuntimeAuthorityId,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
        permission_owner: Option<RegisteredPermissionOwnerPair>,
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
                permission_owner,
            }),
            runtime_authority_id,
            prohibited_content,
        }
    }

    /// Returns only the target-preparation capability paired at this Store's construction.
    #[cfg(target_os = "linux")]
    pub fn local_permission_preparation(
        &self,
    ) -> Result<runne_platform::local_command_linux::LinuxPermissionPreparationV1, EventStoreError>
    {
        self.inner
            .permission_owner
            .as_ref()
            .filter(|owner| owner.validate_retained_owner(&self.runtime_authority_id))
            .map(|owner| owner.native_owner.preparation())
            .ok_or(EventStoreError::Unavailable)
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
            -> Result<T, runne_application::ports::ProjectWorkspaceRepositoryError>,
    ) -> Result<T, runne_application::ports::ProjectWorkspaceRepositoryError> {
        use runne_application::ports::ProjectWorkspaceRepositoryError as Error;

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
            -> Result<T, runne_application::ports::ProjectWorkspaceRepositoryError>,
    ) -> Result<T, runne_application::ports::ProjectWorkspaceRepositoryError> {
        use runne_application::ports::ProjectWorkspaceRepositoryError as Error;

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
