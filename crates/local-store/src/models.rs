#[derive(Debug, Eq, PartialEq)]
pub struct LocalProject {
    pub id: i64,
    pub name: String,
    pub path: PathBuf,
    pub last_opened_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalStoreDiagnostics {
    pub schema_version: u32,
    pub database_generation: u64,
    pub project_count: u64,
}

#[derive(Debug, Error)]
pub enum StoreOpenError {
    #[error("unsupported database schema version: {0}")]
    UnsupportedSchema(i64),
    #[error("legacy replay state cannot be migrated safely")]
    LegacyReplayState,
    #[error("pre-v4 migration backup is unavailable")]
    MigrationBackupUnavailable,
    #[error("pre-v5 migration backup recovery requires operator action")]
    PreV5BackupRecoveryRequired,
    #[error("pre-v5 migration backup artifacts conflict")]
    PreV5BackupConflict,
    #[error("pre-v5 migration backup is unsafe or invalid")]
    PreV5BackupInvalid,
    #[error("pre-v5 migration backup does not match the admitted source")]
    PreV5BackupSourceMismatch,
    #[error("recent root migration cannot be completed safely")]
    RecentRootMigrationCorrupt,
    #[error("local schema does not match the admitted version")]
    SchemaCorrupt,
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreV4MigrationBackup {
    pub path: PathBuf,
    pub schema_version: u32,
}

/// Returns the stable side-by-side rollback backup path for a profile database.
///
/// # Errors
///
/// Returns a redacted error when the database has no concrete file name.
pub fn pre_v4_migration_backup_path(database_path: &Path) -> Result<PathBuf, StoreOpenError> {
    migration_backup_path(database_path, "pre-v4")
}

/// Returns the stable side-by-side rollback backup path for a v4 database.
///
/// # Errors
///
/// Returns a redacted error when the database has no concrete file name.
pub fn pre_v5_migration_backup_path(database_path: &Path) -> Result<PathBuf, StoreOpenError> {
    migration_backup_path(database_path, "pre-v5")
}

fn migration_backup_path(database_path: &Path, label: &str) -> Result<PathBuf, StoreOpenError> {
    let file_name = database_path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or(StoreOpenError::MigrationBackupUnavailable)?;
    Ok(database_path.with_file_name(format!("{file_name}.{label}-backup.sqlite3")))
}

/// Reopens and integrity-checks the immutable pre-v4 rollback backup.
///
/// # Errors
///
/// Rejects missing, symlinked, corrupt, or non-v3 backup artifacts.
pub fn verify_pre_v4_migration_backup(
    database_path: &Path,
) -> Result<PreV4MigrationBackup, StoreOpenError> {
    let backup_path = pre_v4_migration_backup_path(database_path)?;
    verify_pre_v4_backup_path(&backup_path)
}

/// Reopens and integrity-checks the immutable pre-v5 rollback backup.
///
/// # Errors
///
/// Rejects missing, symlinked, corrupt, or non-v4 backup artifacts.
pub fn verify_pre_v5_migration_backup(
    database_path: &Path,
) -> Result<PreV4MigrationBackup, StoreOpenError> {
    let backup_path = pre_v5_migration_backup_path(database_path)?;
    verify_pre_v5_backup_path(&backup_path)
}

#[derive(Debug, Error)]
pub enum ProjectOpenError {
    #[error("local project path is not a directory")]
    NotDirectory,
    #[error("local project path has no valid directory name")]
    InvalidName,
    #[error("system clock is before the Unix epoch")]
    InvalidClock,
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("local project path cannot be resolved")]
    PathUnavailable(#[source] std::io::Error),
}

#[derive(Debug, Error)]
pub enum SecurityTransactionError {
    #[error("event generation is out of range")]
    GenerationOutOfRange,
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
}

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("database generation is out of range")]
    GenerationOutOfRange,
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("secure store unavailable")]
    SecureStore(#[from] SecureStoreError),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ReplayScopeKey {
    pub runtime_authority: String,
    pub principal: String,
    pub lineage: String,
    pub scope: String,
    pub binding_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayCheckpoint {
    pub cursor: String,
    pub generation: u64,
    pub event_sequence: u64,
    pub projection_revision: u64,
    pub projection_digest: String,
    pub binding_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredConversationProjection {
    pub payload: Vec<u8>,
    pub revision: u64,
    pub digest: String,
    pub event_sequence: u64,
    pub binding_digest: String,
}

#[derive(Clone, Debug)]
pub struct ReplayTransition<'a> {
    pub scope: &'a ReplayScopeKey,
    pub expected_checkpoint: Option<&'a ReplayCheckpoint>,
    pub event_id: &'a str,
    pub cursor: &'a str,
    pub generation: u64,
    pub event_sequence: u64,
    pub event_bytes: &'a [u8],
    pub event_digest: String,
    pub projection_revision: u64,
    pub projection_bytes: &'a [u8],
    pub projection_digest: String,
}

#[derive(Clone, Copy, Debug)]
pub struct AppliedReplayEvent<'a> {
    pub scope: &'a ReplayScopeKey,
    pub event_id: &'a str,
    pub cursor: &'a str,
    pub generation: u64,
    pub event_sequence: u64,
    pub event_bytes: &'a [u8],
    pub event_digest: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayApplyOutcome {
    Applied { database_generation: u64 },
    AlreadyApplied { database_generation: u64 },
}

#[derive(Debug, Error)]
pub enum ReplayStoreError {
    #[error("anchored replay admission is required for this database")]
    AnchoredAdmissionRequired,
    #[error("replay scope is invalid")]
    InvalidScope,
    #[error("replay digest must be 32-byte lower hex")]
    InvalidDigest,
    #[error("replay cursor must be non-empty")]
    EmptyCursor,
    #[error("stored conversation projection is not valid JSON")]
    CorruptProjectionJson,
    #[error("event digest does not match exact event bytes")]
    EventDigestMismatch,
    #[error("projection digest does not match exact projection bytes")]
    ProjectionDigestMismatch,
    #[error("replay binding does not match stored scope")]
    BindingMismatch,
    #[error("replay cursor does not match stored checkpoint")]
    CursorMismatch,
    #[error("replay generation regressed or does not match stored checkpoint")]
    GenerationMismatch,
    #[error("replay event sequence is not contiguous")]
    NonContiguousSequence,
    #[error("conversation projection revision is not contiguous")]
    NonContiguousRevision,
    #[error("event identity conflict")]
    EventIdentityConflict,
    #[error("replay integer is out of range")]
    IntegerOutOfRange,
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("security state transition failed")]
    Security(#[from] SecurityStateError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseRecoveryState {
    FirstRun,
    Normal,
    RollbackDetected,
    AdvanceAnchor,
    Ambiguous,
    AnchorMissing,
    DatabaseMissing,
}

#[must_use]
pub const fn classify_database_recovery(
    database_generation: Option<u64>,
    anchor_generation: Option<u64>,
    valid_commit_marker: bool,
) -> DatabaseRecoveryState {
    match (database_generation, anchor_generation) {
        (None, None) => DatabaseRecoveryState::FirstRun,
        (Some(database), Some(anchor)) if database == anchor => DatabaseRecoveryState::Normal,
        (Some(database), Some(anchor)) if database < anchor => {
            DatabaseRecoveryState::RollbackDetected
        }
        (Some(database), Some(anchor))
            if database > anchor && database - anchor == 1 && valid_commit_marker =>
        {
            DatabaseRecoveryState::AdvanceAnchor
        }
        (Some(_), Some(_)) => DatabaseRecoveryState::Ambiguous,
        (Some(_), None) => DatabaseRecoveryState::AnchorMissing,
        (None, Some(_)) => DatabaseRecoveryState::DatabaseMissing,
    }
}

pub struct LocalStore {
    connection: Connection,
    security: Option<SecurityContext>,
}
