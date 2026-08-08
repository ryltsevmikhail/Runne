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
        let writer =
            open_managed_connection(Path::new(db_path), ConnectionMode::Writer).map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::Unavailable,
                )
            })?;

        apply_migrations(&writer).map_err(|_| {
            CommitError::StorageFailure(gocode_application::ports::StorageFailureKind::CorruptData)
        })?;

        let reader =
            open_managed_connection(Path::new(db_path), ConnectionMode::Reader).map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::Unavailable,
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
        apply_migrations(&writer).map_err(|_| {
            CommitError::StorageFailure(gocode_application::ports::StorageFailureKind::CorruptData)
        })?;
        readiness_from_managed(&writer).map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;
        readiness_from_managed(&reader).map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;
        publication_from_managed(&writer).map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;
        publication_from_managed(&reader).map_err(|_| {
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
        writer: ManagedConnection,
        reader: ManagedConnection,
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
