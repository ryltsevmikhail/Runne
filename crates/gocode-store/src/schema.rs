//! Database schema — DDL, migrations, and startup PRAGMA gates.
//!
//! The schema consists of:
//! - `schema_version` — tracks applied migrations
//! - `event_log_state` — singleton row for global position counter
//! - `aggregate_streams` — per-aggregate stream metadata
//! - `events` — committed event rows
//! - `command_receipts` — idempotency receipt store

use gocode_domain::id::{EventLogLineageId, validate_uuid_v7_bytes};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use rusqlite::{
    Connection, DatabaseName, OpenFlags, OptionalExtension, Result as SqliteResult, Transaction,
    TransactionBehavior,
};

/// Current schema version. Increment when adding new DDL migrations.
pub const CURRENT_SCHEMA_VERSION: i64 = 13;

/// Fail-closed reason returned before a file-backed database is made writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaOpenDiagnostic {
    ZeroByteDatabase,
    SidecarPresent,
    FileIdentityUncertain,
    UnsafePath,
}

impl fmt::Display for SchemaOpenDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroByteDatabase => "ZeroByteDatabase",
            Self::SidecarPresent => "SidecarPresent",
            Self::FileIdentityUncertain => "FileIdentityUncertain",
            Self::UnsafePath => "UnsafePath",
        })
    }
}

impl std::error::Error for SchemaOpenDiagnostic {}

/// Fail-closed disposition for an explicitly requested V12-to-V11 rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SchemaRollbackError {
    /// The current database is not the exact released V12 schema.
    #[error("schema rollback source is unsupported")]
    UnsupportedSchema,
    /// The upgrade did not produce a usable durable V11 snapshot.
    #[error("schema rollback snapshot is unavailable")]
    SnapshotUnavailable,
    /// At least one authoritative V12 write permanently closed rollback.
    #[error("schema rollback fence is closed")]
    RollbackClosed,
    /// Snapshot identity, digest, ownership, or baseline state did not match.
    #[error("schema rollback snapshot does not match")]
    SnapshotMismatch,
    /// The database or snapshot path was not safe to resolve.
    #[error("schema rollback path is unsafe")]
    UnsafePath,
    /// SQLite or filesystem state prevented a verified rollback.
    #[error("schema rollback store is unavailable")]
    StoreUnavailable,
    /// No atomic new-path authority switch exists for this database owner.
    #[error("schema rollback authority switch is unavailable")]
    AuthoritySwitchUnavailable,
}

fn diagnostic_error(diagnostic: SchemaOpenDiagnostic) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(diagnostic))
}

#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    volume: u64,
    file: u64,
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
struct FileIdentity(same_file::Handle);

fn file_identity(path: &Path) -> Result<FileIdentity, SchemaOpenDiagnostic> {
    if fs::symlink_metadata(path)
        .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?
        .file_type()
        .is_symlink()
    {
        return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata =
            fs::metadata(path).map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        Ok(FileIdentity {
            volume: metadata.dev(),
            file: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        same_file::Handle::from_path(path)
            .map(FileIdentity)
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)
    }
}

#[cfg(unix)]
fn admitted_files() -> &'static Mutex<Vec<FileIdentity>> {
    static FILES: OnceLock<Mutex<Vec<FileIdentity>>> = OnceLock::new();
    FILES.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(windows)]
fn admitted_paths() -> &'static Mutex<Vec<PathBuf>> {
    static PATHS: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
    PATHS.get_or_init(|| Mutex::new(Vec::new()))
}

fn identity_is_admitted(path: &Path) -> Result<bool, SchemaOpenDiagnostic> {
    #[cfg(unix)]
    {
        let identity = file_identity(path)?;
        admitted_files()
            .lock()
            .map(|files| files.contains(&identity))
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)
    }
    #[cfg(windows)]
    {
        admitted_paths()
            .lock()
            .map(|paths| {
                paths
                    .iter()
                    .any(|admitted| same_file::is_same_file(admitted, path).unwrap_or(false))
            })
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)
    }
}

fn admit_identity(path: &Path) -> Result<(), SchemaOpenDiagnostic> {
    #[cfg(unix)]
    {
        let identity = file_identity(path)?;
        fs::canonicalize(path).map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        let mut files = admitted_files()
            .lock()
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        if !files.contains(&identity) {
            files.push(identity);
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        file_identity(path)?;
        let canonical =
            fs::canonicalize(path).map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        let mut paths = admitted_paths()
            .lock()
            .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        if !paths.iter().any(|admitted| admitted == &canonical) {
            paths.push(canonical);
        }
        Ok(())
    }
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    PathBuf::from(sidecar)
}

fn path_is_safe(path: &Path) -> bool {
    !path.to_string_lossy().contains(['?', '#', '%'])
}

/// Reject unsupported existing database schemas without changing the file.
///
/// File-backed verification stores call this before enabling WAL or applying
/// migrations, so an unsupported future or candidate schema remains untouched.
pub fn preflight_existing_file(db_path: &Path) -> SqliteResult<()> {
    if !path_is_safe(db_path) {
        return Err(diagnostic_error(SchemaOpenDiagnostic::UnsafePath));
    }
    let identity = file_identity(db_path).map_err(diagnostic_error)?;
    let metadata = fs::metadata(db_path)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    if metadata.len() == 0 {
        return Err(diagnostic_error(SchemaOpenDiagnostic::ZeroByteDatabase));
    }
    let sidecar_present = existing_sidecar_present(db_path);
    if sidecar_present && !identity_is_admitted(db_path).map_err(diagnostic_error)? {
        return Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent));
    }
    if sidecar_present {
        return Ok(());
    }

    let immutable_uri = immutable_read_only_uri(db_path).map_err(diagnostic_error)?;
    let conn = Connection::open_with_flags(
        immutable_uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    classify_existing_connection(&conn)?;
    drop(conn);
    if file_identity(db_path).map_err(diagnostic_error)? != identity {
        return Err(diagnostic_error(
            SchemaOpenDiagnostic::FileIdentityUncertain,
        ));
    }
    Ok(())
}

/// Opens one already-classified database read-only without creating WAL
/// sidecars when the main file is self-contained.
///
/// An already-admitted hot WAL in the current process uses SQLite's normal
/// read-only view so committed WAL data is not ignored.
pub fn open_existing_read_only(db_path: &Path) -> SqliteResult<Connection> {
    preflight_existing_file(db_path)?;
    if existing_sidecar_present(db_path) {
        return Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY);
    }
    let immutable_uri = immutable_read_only_uri(db_path).map_err(diagnostic_error)?;
    Connection::open_with_flags(
        immutable_uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

/// Validates an owner-private hot-WAL file set, runs an exact read-only
/// protected-runtime check, and admits only that unchanged file identity for
/// the next writable open in this process.
///
/// This is deliberately separate from [`open_existing_read_only`]: arbitrary
/// databases with WAL sidecars remain rejected. The caller must validate its
/// signed stable runtime binding in `validate`; a rejected validation never
/// admits the file for a writable open.
pub fn with_protected_recovery_read_only_admission<F>(
    db_path: &Path,
    validate: F,
) -> SqliteResult<()>
where
    F: FnOnce(&Connection) -> SqliteResult<()>,
{
    #[cfg(not(unix))]
    {
        let _ = (db_path, validate);
        return Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent));
    }
    #[cfg(unix)]
    {
        validate_owner_private_recovery_files(db_path).map_err(diagnostic_error)?;
        let identity = file_identity(db_path).map_err(diagnostic_error)?;
        let connection = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        classify_existing_connection(&connection)?;
        validate(&connection)?;
        if file_identity(db_path).map_err(diagnostic_error)? != identity {
            return Err(diagnostic_error(
                SchemaOpenDiagnostic::FileIdentityUncertain,
            ));
        }
        validate_owner_private_recovery_files(db_path).map_err(diagnostic_error)?;
        admit_identity(db_path).map_err(diagnostic_error)
    }
}

#[cfg(unix)]
fn validate_owner_private_recovery_files(db_path: &Path) -> Result<(), SchemaOpenDiagnostic> {
    use std::os::unix::fs::MetadataExt as _;

    if !db_path.is_absolute() || !path_is_safe(db_path) || !existing_sidecar_present(db_path) {
        return Err(SchemaOpenDiagnostic::SidecarPresent);
    }
    let daemon_dir = db_path
        .parent()
        .ok_or(SchemaOpenDiagnostic::FileIdentityUncertain)?;
    let runtime_root = daemon_dir
        .parent()
        .ok_or(SchemaOpenDiagnostic::FileIdentityUncertain)?;
    let root_metadata = fs::symlink_metadata(runtime_root)
        .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || root_metadata.mode() & 0o077 != 0
    {
        return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
    }
    let owner = root_metadata.uid();
    let daemon_metadata = fs::symlink_metadata(daemon_dir)
        .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
    if daemon_metadata.file_type().is_symlink()
        || !daemon_metadata.is_dir()
        || daemon_metadata.uid() != owner
        || daemon_metadata.mode() & 0o077 != 0
    {
        return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
    }

    for path in [
        db_path.to_path_buf(),
        sidecar_path(db_path, "-wal"),
        sidecar_path(db_path, "-shm"),
    ] {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if path != db_path && error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(_) => return Err(SchemaOpenDiagnostic::FileIdentityUncertain),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != owner
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(SchemaOpenDiagnostic::FileIdentityUncertain);
        }
    }
    Ok(())
}

fn existing_sidecar_present(db_path: &Path) -> bool {
    ["-wal", "-shm"]
        .into_iter()
        .any(|suffix| sidecar_path(db_path, suffix).exists())
}

fn immutable_read_only_uri(path: &Path) -> Result<String, SchemaOpenDiagnostic> {
    let text = path
        .as_os_str()
        .to_str()
        .ok_or(SchemaOpenDiagnostic::UnsafePath)?;
    let mut uri = String::with_capacity(text.len() + 32);
    uri.push_str("file:");
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut uri, "%{byte:02X}")
                .map_err(|_| SchemaOpenDiagnostic::FileIdentityUncertain)?;
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}

/// Classify an existing database before any pragma or statement that can
/// mutate the main database or its sidecars.
fn classify_existing_connection(conn: &Connection) -> SqliteResult<()> {
    let user_version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if user_version > CURRENT_SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }

    let has_version_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version')",
        [],
        |row| row.get(0),
    )?;
    if !has_version_table {
        return Err(rusqlite::Error::InvalidQuery);
    }

    let schema_version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if schema_version == 8 && is_released_v8(conn)? {
        return Ok(());
    }
    let compatible = match schema_version {
        9 => is_released_strict_v9(conn, schema_version)?,
        10 => is_released_provider_v10(conn, schema_version)?,
        11 => is_released_provider_v11(conn, schema_version)?,
        12 => is_released_provider_v12(conn, schema_version)?,
        13 => is_released_provider_v13(conn, schema_version)?,
        _ => false,
    };
    if compatible {
        return Ok(());
    }
    Err(rusqlite::Error::InvalidQuery)
}

fn is_released_v8(conn: &Connection) -> SqliteResult<bool> {
    let version_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))?;
    let min_version: i64 = conn.query_row(
        "SELECT COALESCE(MIN(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if version_count != 8 || min_version != 1 {
        return Ok(false);
    }

    const RELEASED_V8_TABLES: &[&str] = &[
        "event_log_state",
        "aggregate_streams",
        "events",
        "command_receipts",
        "migration_plans",
        "migration_transitions",
        "migration_evidence",
        "routing_snapshots",
        "routing_head",
        "runtime_bindings",
        "migration_reports",
        "cutover_manifests",
        "rollback_manifests",
        "retirement_manifests",
        "migration_receipts",
        "migration_audit",
        "routing_dispatch_intents",
        "security_dispatch_intents",
        "security_authorization_decisions",
        "security_budget_consumptions",
        "security_audit_pre_effect",
        "security_permit_claims",
        "_authority",
        "_daemon_info",
        "_replay_subscriptions",
    ];
    RELEASED_V8_TABLES.iter().try_fold(true, |matches, table| {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )?;
        Ok(matches && exists)
    })
}

struct PrivateDatabaseBackup {
    filename: String,
    digest: [u8; 32],
}

struct V11UpgradeSnapshot {
    backup: Option<PrivateDatabaseBackup>,
    baseline_event_next_position: i64,
    baseline_provider_prepared_count: i64,
    baseline_provider_attempt_count: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaMaintenancePoint {
    V11SnapshotCaptured,
    RollbackPreliminaryFenceChecked,
    RollbackSnapshotVerified,
    RollbackBeforeCutover,
}

struct V12UpgradeFenceRow {
    snapshot_filename: Option<String>,
    snapshot_digest: Option<Vec<u8>>,
    source_version: i64,
    target_version: i64,
    baseline_event_next_position: i64,
    baseline_provider_prepared_count: i64,
    baseline_provider_attempt_count: i64,
}

fn load_v12_upgrade_fence(conn: &Connection) -> SqliteResult<Option<V12UpgradeFenceRow>> {
    conn.query_row(
        "SELECT snapshot_filename, snapshot_digest, source_version,
                target_version, baseline_event_next_position,
                baseline_provider_prepared_count,
                baseline_provider_attempt_count
         FROM schema_upgrade_fence WHERE id = 1",
        [],
        |row| {
            Ok(V12UpgradeFenceRow {
                snapshot_filename: row.get(0)?,
                snapshot_digest: row.get(1)?,
                source_version: row.get(2)?,
                target_version: row.get(3)?,
                baseline_event_next_position: row.get(4)?,
                baseline_provider_prepared_count: row.get(5)?,
                baseline_provider_attempt_count: row.get(6)?,
            })
        },
    )
    .optional()
}

fn v12_write_latch_closed(conn: &Connection) -> SqliteResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_upgrade_write_latch WHERE id = 1)",
        [],
        |row| row.get(0),
    )
}

fn create_v11_upgrade_snapshot(conn: &Connection) -> SqliteResult<V11UpgradeSnapshot> {
    let version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if version != 11 || !is_released_provider_v11(conn, 11)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let snapshot = V11UpgradeSnapshot {
        backup: match conn.path() {
            Some(path) if !path.is_empty() => {
                let source = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                if !is_released_provider_v11(&source, 11)? {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Some(create_private_database_backup(&source, "v11-pre-v12", 11)?)
            }
            _ => None,
        },
        baseline_event_next_position: conn.query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?,
        baseline_provider_prepared_count: conn.query_row(
            "SELECT COUNT(*) FROM provider_prepared_requests",
            [],
            |row| row.get(0),
        )?,
        baseline_provider_attempt_count: conn.query_row(
            "SELECT COUNT(*) FROM provider_dispatch_attempts",
            [],
            |row| row.get(0),
        )?,
    };
    Ok(snapshot)
}

fn create_private_database_backup(
    conn: &Connection,
    label: &str,
    expected_version: i64,
) -> SqliteResult<PrivateDatabaseBackup> {
    let source = conn
        .path()
        .filter(|path| !path.is_empty())
        .ok_or(rusqlite::Error::InvalidPath(PathBuf::new()))?;
    let source_path = fs::canonicalize(source)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    if !path_is_safe(&source_path) {
        return Err(diagnostic_error(SchemaOpenDiagnostic::UnsafePath));
    }
    let parent = source_path
        .parent()
        .ok_or_else(|| rusqlite::Error::InvalidPath(source_path.clone()))?;
    let source_filename = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| rusqlite::Error::InvalidPath(source_path.clone()))?;
    let mut nonce = [0_u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let nonce = nonce
        .iter()
        .fold(String::with_capacity(32), |mut encoded, byte| {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "{byte:02x}");
            encoded
        });
    let filename = format!("{source_filename}.gocode-{label}-{nonce}.sqlite");
    if filename.len() > 255 || !safe_snapshot_filename(&filename) {
        return Err(rusqlite::Error::InvalidPath(PathBuf::from(filename)));
    }
    let path = parent.join(&filename);
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let identity = file_identity(&path).map_err(diagnostic_error)?;
    file.sync_all()
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    drop(file);

    conn.backup(DatabaseName::Main, &path, None)?;
    secure_file_permissions(&path)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    if file_identity(&path).map_err(diagnostic_error)? != identity {
        return Err(diagnostic_error(
            SchemaOpenDiagnostic::FileIdentityUncertain,
        ));
    }
    let snapshot = Connection::open(&path)?;
    let journal_mode: String =
        snapshot.query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let version: i64 = snapshot.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    let integrity: String = snapshot.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let mut foreign_key_check = snapshot.prepare("PRAGMA foreign_key_check")?;
    if version != expected_version || integrity != "ok" || foreign_key_check.exists([])? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    drop(foreign_key_check);
    drop(snapshot);
    let snapshot_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    snapshot_file
        .sync_all()
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    sync_snapshot_parent(&path)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let digest = sha256_file(&path)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    Ok(PrivateDatabaseBackup { filename, digest })
}

#[cfg(unix)]
fn sync_snapshot_parent(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "snapshot path has no parent",
        )
    })?;
    fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_snapshot_parent(_: &Path) -> std::io::Result<()> {
    Ok(())
}

fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn safe_snapshot_filename(filename: &str) -> bool {
    !filename.is_empty()
        && filename.len() <= 255
        && !filename.contains(['/', '\\'])
        && Path::new(filename)
            .file_name()
            .and_then(|name| name.to_str())
            == Some(filename)
}

fn authoritative_v12_tables(conn: &Connection) -> SqliteResult<Vec<String>> {
    let mut statement = conn.prepare(
        "SELECT name FROM sqlite_master
         WHERE type = 'table'
           AND name NOT LIKE 'sqlite_%'
           AND name NOT IN (
               'schema_version',
               'schema_upgrade_fence',
               'schema_upgrade_write_latch'
           )
         ORDER BY name",
    )?;
    statement
        .query_map([], |row| row.get::<_, String>(0))?
        .map(|name| {
            let name = name?;
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(name)
        })
        .collect()
}

fn v12_fence_trigger(table: &str, operation: &str) -> SqliteResult<(String, String)> {
    let timing = match operation {
        "insert" => "INSERT",
        "update" => "UPDATE",
        "delete" => "DELETE",
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let name = format!("schema_v12_fence_{table}_{operation}");
    let sql = format!(
        "CREATE TRIGGER \"{name}\" AFTER {timing} ON \"{table}\"
         BEGIN
             INSERT INTO schema_upgrade_write_latch (id, closed)
             VALUES (1, 1)
             ON CONFLICT(id) DO NOTHING;
         END"
    );
    Ok((name, sql))
}

fn v12_guard_triggers() -> [(&'static str, &'static str, &'static str); 5] {
    [
        (
            "schema_v12_guard_fence_insert",
            "schema_upgrade_fence",
            "CREATE TRIGGER \"schema_v12_guard_fence_insert\"
             BEFORE INSERT ON \"schema_upgrade_fence\"
             BEGIN SELECT RAISE(ABORT, 'schema upgrade fence is immutable'); END",
        ),
        (
            "schema_v12_guard_fence_update",
            "schema_upgrade_fence",
            "CREATE TRIGGER \"schema_v12_guard_fence_update\"
             BEFORE UPDATE ON \"schema_upgrade_fence\"
             BEGIN SELECT RAISE(ABORT, 'schema upgrade fence is immutable'); END",
        ),
        (
            "schema_v12_guard_fence_delete",
            "schema_upgrade_fence",
            "CREATE TRIGGER \"schema_v12_guard_fence_delete\"
             BEFORE DELETE ON \"schema_upgrade_fence\"
             BEGIN SELECT RAISE(ABORT, 'schema upgrade fence is immutable'); END",
        ),
        (
            "schema_v12_guard_latch_update",
            "schema_upgrade_write_latch",
            "CREATE TRIGGER \"schema_v12_guard_latch_update\"
             BEFORE UPDATE ON \"schema_upgrade_write_latch\"
             BEGIN SELECT RAISE(ABORT, 'schema upgrade latch is irreversible'); END",
        ),
        (
            "schema_v12_guard_latch_delete",
            "schema_upgrade_write_latch",
            "CREATE TRIGGER \"schema_v12_guard_latch_delete\"
             BEFORE DELETE ON \"schema_upgrade_write_latch\"
             BEGIN SELECT RAISE(ABORT, 'schema upgrade latch is irreversible'); END",
        ),
    ]
}

fn install_v12_fence_triggers(conn: &Connection) -> SqliteResult<()> {
    for table in authoritative_v12_tables(conn)? {
        for operation in ["insert", "update", "delete"] {
            let (_, sql) = v12_fence_trigger(&table, operation)?;
            conn.execute_batch(&sql)?;
        }
    }
    for (_, _, sql) in v12_guard_triggers() {
        conn.execute_batch(sql)?;
    }
    Ok(())
}

fn install_missing_v12_fence_triggers(conn: &Connection) -> SqliteResult<()> {
    for table in authoritative_v12_tables(conn)? {
        for operation in ["insert", "update", "delete"] {
            let (name, sql) = v12_fence_trigger(&table, operation)?;
            let exists: bool = conn.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'trigger' AND name = ?1
                 )",
                [&name],
                |row| row.get(0),
            )?;
            if !exists {
                conn.execute_batch(&sql)?;
            }
        }
    }
    Ok(())
}

fn v12_fence_triggers_match(conn: &Connection) -> SqliteResult<bool> {
    let tables = authoritative_v12_tables(conn)?;
    let expected_count = i64::try_from(
        tables
            .len()
            .checked_mul(3)
            .and_then(|count| count.checked_add(v12_guard_triggers().len()))
            .ok_or(rusqlite::Error::InvalidQuery)?,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let actual_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'",
        [],
        |row| row.get(0),
    )?;
    if actual_count != expected_count {
        return Ok(false);
    }
    for table in tables {
        for operation in ["insert", "update", "delete"] {
            let (name, expected_sql) = v12_fence_trigger(&table, operation)?;
            let actual: Option<(String, String)> = conn
                .query_row(
                    "SELECT tbl_name, sql FROM sqlite_master
                     WHERE type = 'trigger' AND name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((actual_table, actual_sql)) = actual else {
                return Ok(false);
            };
            if actual_table != table || normalize_sql(&actual_sql) != normalize_sql(&expected_sql) {
                return Ok(false);
            }
        }
    }
    for (name, table, expected_sql) in v12_guard_triggers() {
        let actual: Option<(String, String)> = conn
            .query_row(
                "SELECT tbl_name, sql FROM sqlite_master
                 WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((actual_table, actual_sql)) = actual else {
            return Ok(false);
        };
        if actual_table != table || normalize_sql(&actual_sql) != normalize_sql(expected_sql) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Apply all schema migrations up to [`CURRENT_SCHEMA_VERSION`].
///
/// Idempotent — only runs migrations not yet applied.
pub fn apply_migrations(conn: &Connection) -> SqliteResult<()> {
    apply_migrations_with_maintenance_hook(conn, None)
}

fn apply_migrations_with_maintenance_hook(
    conn: &Connection,
    maintenance_hook: Option<&dyn Fn(SchemaMaintenancePoint)>,
) -> SqliteResult<()> {
    apply_migrations_through(conn, CURRENT_SCHEMA_VERSION, maintenance_hook)
}

fn apply_migrations_through(
    conn: &Connection,
    target_version: i64,
    maintenance_hook: Option<&dyn Fn(SchemaMaintenancePoint)>,
) -> SqliteResult<()> {
    if !(1..=CURRENT_SCHEMA_VERSION).contains(&target_version) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let has_version_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version')",
        [],
        |row| row.get(0),
    )?;
    if has_version_table {
        let existing_version: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )?;
        let compatible = match existing_version {
            0..=8 => true,
            9 => is_released_strict_v9(conn, existing_version)?,
            10 => is_released_provider_v10(conn, existing_version)?,
            11 => is_released_provider_v11(conn, existing_version)?,
            12 => is_released_provider_v12(conn, existing_version)?,
            13 => is_released_provider_v13(conn, existing_version)?,
            _ => false,
        };
        if !compatible {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;

    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if current_version < 1 && target_version >= 1 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V1)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (1)", [])?;
        tx.commit()?;
    }

    if current_version < 2 && target_version >= 2 {
        // Keep DDL, V1 backfill, and the version marker in one transaction.
        // `Transaction` rolls back on drop if any ALTER or rename fails.
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V2)?;
        tx.execute(
            "UPDATE events
             SET correlation_id = taskrun_id,
                 correlation_type = 1,
                 integrity_profile = 1",
            [],
        )?;
        tx.execute("INSERT INTO schema_version (version) VALUES (2)", [])?;
        tx.commit()?;
    }

    if current_version < 3 && target_version >= 3 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V3)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (3)", [])?;
        tx.commit()?;
    }

    if current_version < 4 && target_version >= 4 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V4)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (4)", [])?;
        tx.commit()?;
    }

    if current_version < 5 && target_version >= 5 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V5)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (5)", [])?;
        tx.commit()?;
    }

    if current_version < 6 && target_version >= 6 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V6)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (6)", [])?;
        tx.commit()?;
    }

    if current_version < 7 && target_version >= 7 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V7)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (7)", [])?;
        tx.commit()?;
    }

    if current_version < 8 && target_version >= 8 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V8)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (8)", [])?;
        tx.commit()?;
    }

    if current_version < 9 && target_version >= 9 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V9)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (9)", [])?;
        tx.commit()?;
    }

    if current_version < 10 && target_version >= 10 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V10)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (10)", [])?;
        tx.commit()?;
    }

    if current_version < 11 && target_version >= 11 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V11)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (11)", [])?;
        tx.commit()?;
    }

    if current_version < 12 && target_version >= 12 {
        if conn.path().is_some_and(|path| !path.is_empty()) {
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;",
            )?;
        }
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
        let snapshot = create_v11_upgrade_snapshot(&tx)?;
        if let Some(hook) = maintenance_hook {
            hook(SchemaMaintenancePoint::V11SnapshotCaptured);
        }
        tx.execute_batch(MIGRATION_V12)?;
        tx.execute(
            "INSERT INTO schema_upgrade_fence (
                id, source_version, target_version, snapshot_filename,
                snapshot_digest, baseline_event_next_position,
                baseline_provider_prepared_count,
                baseline_provider_attempt_count
             ) VALUES (1, 11, 12, ?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                snapshot.backup.as_ref().map(|backup| &backup.filename),
                snapshot
                    .backup
                    .as_ref()
                    .map(|backup| backup.digest.as_slice()),
                snapshot.baseline_event_next_position,
                snapshot.baseline_provider_prepared_count,
                snapshot.baseline_provider_attempt_count,
            ],
        )?;
        install_v12_fence_triggers(&tx)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (12)", [])?;
        tx.commit()?;
    }

    if current_version < 13 && target_version >= 13 {
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
        tx.execute_batch(MIGRATION_V13)?;
        install_missing_v12_fence_triggers(&tx)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (13)", [])?;
        tx.commit()?;
    }

    if current_version < target_version {
        // Preflight classifies the immutable main database without consulting
        // a hot WAL. Publish completed schema migrations before another
        // process or connection attempts admission.
        conn.execute_batch("PRAGMA wal_checkpoint(FULL);")?;
    }

    Ok(())
}

/// Verifies the exact V11 snapshot while the V12 write fence is open.
///
/// In-place restore is prohibited. Until the database owner provides a
/// new-path restore, atomic authority/generation switch, and stale-handle
/// fencing, an otherwise eligible rollback returns
/// [`SchemaRollbackError::AuthoritySwitchUnavailable`] without mutating the
/// authoritative database. Any committed authoritative insert, update, or
/// delete after migration permanently returns
/// [`SchemaRollbackError::RollbackClosed`].
pub fn rollback_pre_v12_snapshot(db_path: &Path) -> Result<(), SchemaRollbackError> {
    rollback_pre_v12_snapshot_with_hook(db_path, None)
}

fn rollback_pre_v12_snapshot_with_hook(
    db_path: &Path,
    maintenance_hook: Option<&dyn Fn(SchemaMaintenancePoint)>,
) -> Result<(), SchemaRollbackError> {
    if !db_path.is_absolute() || !path_is_safe(db_path) {
        return Err(SchemaRollbackError::UnsafePath);
    }
    let original_identity = file_identity(db_path).map_err(|_| SchemaRollbackError::UnsafePath)?;
    let connection = open_with_pragmas(db_path.to_str().ok_or(SchemaRollbackError::UnsafePath)?)
        .map_err(|_| SchemaRollbackError::StoreUnavailable)?;
    let version: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?;
    if !is_supported_pre_v12_rollback_source(&connection, version)
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?
    {
        return Err(SchemaRollbackError::UnsupportedSchema);
    }
    let fence = load_v12_upgrade_fence(&connection)
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?
        .ok_or(SchemaRollbackError::UnsupportedSchema)?;
    if v12_write_latch_closed(&connection).map_err(|_| SchemaRollbackError::UnsupportedSchema)?
        || !current_v12_high_water_matches(&connection, &fence)?
    {
        return Err(SchemaRollbackError::RollbackClosed);
    }
    if let Some(hook) = maintenance_hook {
        hook(SchemaMaintenancePoint::RollbackPreliminaryFenceChecked);
    }
    let snapshot_filename = fence
        .snapshot_filename
        .as_deref()
        .ok_or(SchemaRollbackError::SnapshotUnavailable)?;
    let snapshot_digest = fence
        .snapshot_digest
        .as_deref()
        .ok_or(SchemaRollbackError::SnapshotUnavailable)?;
    let snapshot_path = resolve_private_snapshot(db_path, snapshot_filename)?;
    let actual_digest =
        sha256_file(&snapshot_path).map_err(|_| SchemaRollbackError::SnapshotMismatch)?;
    if snapshot_digest != actual_digest {
        return Err(SchemaRollbackError::SnapshotMismatch);
    }
    let snapshot_identity =
        file_identity(&snapshot_path).map_err(|_| SchemaRollbackError::SnapshotMismatch)?;

    let snapshot = open_existing_read_only(&snapshot_path)
        .map_err(|_| SchemaRollbackError::SnapshotMismatch)?;
    if !is_released_provider_v11(&snapshot, 11)
        .map_err(|_| SchemaRollbackError::SnapshotMismatch)?
    {
        return Err(SchemaRollbackError::SnapshotMismatch);
    }
    let snapshot_event_next_position: i64 = snapshot
        .query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SchemaRollbackError::SnapshotMismatch)?;
    let snapshot_prepared_count: i64 = snapshot
        .query_row(
            "SELECT COUNT(*) FROM provider_prepared_requests",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SchemaRollbackError::SnapshotMismatch)?;
    let snapshot_attempt_count: i64 = snapshot
        .query_row(
            "SELECT COUNT(*) FROM provider_dispatch_attempts",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SchemaRollbackError::SnapshotMismatch)?;
    if snapshot_event_next_position != fence.baseline_event_next_position
        || snapshot_prepared_count != fence.baseline_provider_prepared_count
        || snapshot_attempt_count != fence.baseline_provider_attempt_count
    {
        return Err(SchemaRollbackError::SnapshotMismatch);
    }
    if let Some(hook) = maintenance_hook {
        hook(SchemaMaintenancePoint::RollbackSnapshotVerified);
    }

    recheck_rollback_fence(
        &connection,
        db_path,
        &original_identity,
        &snapshot_path,
        snapshot_digest,
        &snapshot_identity,
        &fence,
    )?;

    if let Some(hook) = maintenance_hook {
        hook(SchemaMaintenancePoint::RollbackBeforeCutover);
    }
    recheck_rollback_fence(
        &connection,
        db_path,
        &original_identity,
        &snapshot_path,
        snapshot_digest,
        &snapshot_identity,
        &fence,
    )?;

    Err(SchemaRollbackError::AuthoritySwitchUnavailable)
}

fn current_v12_high_water_matches(
    conn: &Connection,
    fence: &V12UpgradeFenceRow,
) -> Result<bool, SchemaRollbackError> {
    let event_next_position: i64 = conn
        .query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?;
    let prepared_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM provider_prepared_requests",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?;
    let attempt_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM provider_dispatch_attempts",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?;
    Ok(event_next_position == fence.baseline_event_next_position
        && prepared_count == fence.baseline_provider_prepared_count
        && attempt_count == fence.baseline_provider_attempt_count)
}

fn recheck_rollback_fence(
    conn: &Connection,
    db_path: &Path,
    expected_database_identity: &FileIdentity,
    snapshot_path: &Path,
    expected_snapshot_digest: &[u8],
    expected_snapshot_identity: &FileIdentity,
    fence: &V12UpgradeFenceRow,
) -> Result<(), SchemaRollbackError> {
    if &file_identity(db_path).map_err(|_| SchemaRollbackError::UnsafePath)?
        != expected_database_identity
    {
        return Err(SchemaRollbackError::UnsafePath);
    }
    if &file_identity(snapshot_path).map_err(|_| SchemaRollbackError::SnapshotMismatch)?
        != expected_snapshot_identity
    {
        return Err(SchemaRollbackError::SnapshotMismatch);
    }
    if sha256_file(snapshot_path)
        .map_err(|_| SchemaRollbackError::SnapshotMismatch)?
        .as_slice()
        != expected_snapshot_digest
    {
        return Err(SchemaRollbackError::SnapshotMismatch);
    }
    let version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?;
    if !is_supported_pre_v12_rollback_source(conn, version)
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?
        || v12_write_latch_closed(conn).map_err(|_| SchemaRollbackError::UnsupportedSchema)?
        || !current_v12_high_water_matches(conn, fence)?
    {
        return Err(SchemaRollbackError::RollbackClosed);
    }
    Ok(())
}

fn is_supported_pre_v12_rollback_source(conn: &Connection, version: i64) -> SqliteResult<bool> {
    match version {
        12 => is_released_provider_v12(conn, version),
        13 => is_released_provider_v13(conn, version),
        _ => Ok(false),
    }
}

fn resolve_private_snapshot(
    db_path: &Path,
    snapshot_filename: &str,
) -> Result<PathBuf, SchemaRollbackError> {
    if !safe_snapshot_filename(snapshot_filename) {
        return Err(SchemaRollbackError::UnsafePath);
    }
    let database = fs::canonicalize(db_path).map_err(|_| SchemaRollbackError::UnsafePath)?;
    let parent = database.parent().ok_or(SchemaRollbackError::UnsafePath)?;
    let snapshot = parent.join(snapshot_filename);
    let metadata =
        fs::symlink_metadata(&snapshot).map_err(|_| SchemaRollbackError::SnapshotUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SchemaRollbackError::SnapshotMismatch);
    }
    let canonical_snapshot =
        fs::canonicalize(&snapshot).map_err(|_| SchemaRollbackError::SnapshotMismatch)?;
    if canonical_snapshot.parent() != Some(parent) {
        return Err(SchemaRollbackError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let database_metadata =
            fs::metadata(&database).map_err(|_| SchemaRollbackError::SnapshotMismatch)?;
        if metadata.uid() != database_metadata.uid()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(SchemaRollbackError::SnapshotMismatch);
        }
    }
    Ok(canonical_snapshot)
}

fn is_released_strict_v9(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 9 {
        return Ok(false);
    }
    if !table_shape_matches(
        conn,
        "verification_evidence",
        &VERIFICATION_EVIDENCE_COLUMNS,
    )? || !table_shape_matches(conn, "consumption_intents", &CONSUMPTION_INTENT_COLUMNS)?
        || !table_shape_matches(conn, "schema_lineage", &SCHEMA_LINEAGE_COLUMNS)?
        || !table_sql_matches(
            conn,
            "verification_evidence",
            CANONICAL_VERIFICATION_EVIDENCE_SQL,
        )?
        || !table_sql_matches(
            conn,
            "consumption_intents",
            CANONICAL_CONSUMPTION_INTENTS_SQL,
        )?
        || !table_sql_matches(conn, "schema_lineage", CANONICAL_SCHEMA_LINEAGE_SQL)?
        || !index_matches(
            conn,
            "idx_evidence_run",
            "verification_evidence",
            &["run_id"],
        )?
    {
        return Ok(false);
    }

    let marker_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM schema_lineage", [], |row| row.get(0))?;
    let marker_matches: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_lineage WHERE schema_version = 9 AND provenance = 'released-v8-to-strict-v9')",
        [],
        |row| row.get(0),
    )?;
    if marker_count != 1 || !marker_matches || has_candidate_remnant(conn)? {
        return Ok(false);
    }
    Ok(true)
}

fn is_released_provider_v10(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 10 || !is_released_strict_v9(conn, 9)? {
        return Ok(false);
    }
    Ok(table_shape_matches(
        conn,
        "provider_prepared_requests",
        &PROVIDER_PREPARED_COLUMNS,
    )? && table_sql_matches_migration(conn, "provider_prepared_requests", MIGRATION_V10)?
        && table_shape_matches(
            conn,
            "provider_dispatch_attempts",
            &PROVIDER_DISPATCH_COLUMNS,
        )?
        && table_sql_matches_migration(conn, "provider_dispatch_attempts", MIGRATION_V10)?)
}

fn is_released_provider_v11(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 11 || !is_released_provider_v10(conn, 10)? {
        return Ok(false);
    }
    Ok(table_shape_matches(
        conn,
        "provider_effect_authorities",
        &PROVIDER_EFFECT_AUTHORITY_COLUMNS,
    )? && table_sql_matches_migration(conn, "provider_effect_authorities", MIGRATION_V11)?)
}

fn is_released_provider_v12(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 12 {
        return Ok(false);
    }
    Ok(provider_v12_core_matches(conn)?
        && v12_fence_triggers_match(conn)?
        && released_v12_catalog_matches(conn)?)
}

fn provider_v12_core_matches(conn: &Connection) -> SqliteResult<bool> {
    if !is_released_strict_v9(conn, 9)? {
        return Ok(false);
    }
    Ok(table_shape_matches(
        conn,
        "provider_prepared_requests",
        &PROVIDER_PREPARED_V12_COLUMNS,
    )? && table_sql_matches(
        conn,
        "provider_prepared_requests",
        CANONICAL_PROVIDER_PREPARED_V12_SQL,
    )? && table_shape_matches(
        conn,
        "provider_dispatch_attempts",
        &PROVIDER_DISPATCH_V12_COLUMNS,
    )? && table_sql_matches_migration(conn, "provider_dispatch_attempts", MIGRATION_V12)?
        && table_shape_matches(
            conn,
            "provider_effect_authorities",
            &PROVIDER_EFFECT_AUTHORITY_COLUMNS,
        )?
        && table_sql_matches_migration(conn, "provider_effect_authorities", MIGRATION_V11)?
        && table_shape_matches(conn, "schema_upgrade_fence", &SCHEMA_UPGRADE_FENCE_COLUMNS)?
        && table_sql_matches_migration(conn, "schema_upgrade_fence", MIGRATION_V12)?
        && table_shape_matches(
            conn,
            "schema_upgrade_write_latch",
            &SCHEMA_UPGRADE_WRITE_LATCH_COLUMNS,
        )?
        && table_sql_matches_migration(conn, "schema_upgrade_write_latch", MIGRATION_V12)?
        && v12_upgrade_fence_matches(conn)?
        && v12_write_latch_matches(conn)?)
}

fn is_released_provider_v13(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 13 || !provider_v12_core_matches(conn)? {
        return Ok(false);
    }
    Ok(table_shape_matches(
        conn,
        "provider_runtime_authority_state",
        &PROVIDER_RUNTIME_AUTHORITY_STATE_COLUMNS,
    )? && table_sql_matches_migration(conn, "provider_runtime_authority_state", MIGRATION_V13)?
        && table_shape_matches(
            conn,
            "provider_execution_admissions",
            &PROVIDER_EXECUTION_ADMISSION_COLUMNS,
        )?
        && table_sql_matches_migration(conn, "provider_execution_admissions", MIGRATION_V13)?
        && table_shape_matches(
            conn,
            "provider_budget_reservations",
            &PROVIDER_BUDGET_RESERVATION_COLUMNS,
        )?
        && table_sql_matches_migration(conn, "provider_budget_reservations", MIGRATION_V13)?
        && table_shape_matches(
            conn,
            "provider_journal_key_refs",
            &PROVIDER_JOURNAL_KEY_REF_COLUMNS,
        )?
        && table_sql_matches_migration(conn, "provider_journal_key_refs", MIGRATION_V13)?
        && table_shape_matches(
            conn,
            "provider_encryption_nonces",
            &PROVIDER_ENCRYPTION_NONCE_COLUMNS,
        )?
        && table_sql_matches_migration(conn, "provider_encryption_nonces", MIGRATION_V13)?
        && table_shape_matches(conn, "provider_poll_flights", &PROVIDER_POLL_FLIGHT_COLUMNS)?
        && table_sql_matches_migration(conn, "provider_poll_flights", MIGRATION_V13)?
        && table_shape_matches(
            conn,
            "provider_stream_journal",
            &PROVIDER_STREAM_JOURNAL_COLUMNS,
        )?
        && table_sql_matches_migration(conn, "provider_stream_journal", MIGRATION_V13)?
        && table_shape_matches(
            conn,
            "provider_accounting_settlements",
            &PROVIDER_ACCOUNTING_SETTLEMENT_COLUMNS,
        )?
        && table_sql_matches_migration(conn, "provider_accounting_settlements", MIGRATION_V13)?
        && table_shape_matches(
            conn,
            "provider_terminal_outbox",
            &PROVIDER_TERMINAL_OUTBOX_COLUMNS,
        )?
        && table_sql_matches_migration(conn, "provider_terminal_outbox", MIGRATION_V13)?
        && v12_fence_triggers_match(conn)?
        && released_v13_catalog_matches(conn)?)
}

type ColumnShape = (&'static str, &'static str, bool, i64);

const VERIFICATION_EVIDENCE_COLUMNS: [ColumnShape; 12] = [
    ("evidence_id", "BLOB", false, 1),
    ("run_id", "BLOB", true, 0),
    ("profile_id", "BLOB", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("layer", "INTEGER", true, 0),
    ("evidence_type", "INTEGER", true, 0),
    ("evidence_digest", "BLOB", true, 0),
    ("content_ref", "TEXT", true, 0),
    ("source", "TEXT", true, 0),
    ("producer_identity", "TEXT", true, 0),
    ("sensitivity", "INTEGER", true, 0),
    ("verified_by", "TEXT", true, 0),
];
const CONSUMPTION_INTENT_COLUMNS: [ColumnShape; 6] = [
    ("intent_id", "BLOB", false, 1),
    ("idempotency_key", "TEXT", true, 0),
    ("state", "TEXT", true, 0),
    ("gate_head_snapshot_digest", "BLOB", true, 0),
    ("target_artifact_digest", "BLOB", true, 0),
    ("integrity_digest", "BLOB", true, 0),
];
const SCHEMA_LINEAGE_COLUMNS: [ColumnShape; 2] = [
    ("schema_version", "INTEGER", false, 1),
    ("provenance", "TEXT", true, 0),
];
const PROVIDER_PREPARED_COLUMNS: [ColumnShape; 5] = [
    ("call_id", "BLOB", false, 1),
    ("prepared_digest", "BLOB", true, 0),
    ("render_digest", "BLOB", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("record_digest", "BLOB", true, 0),
];
const PROVIDER_PREPARED_V12_COLUMNS: [ColumnShape; 6] = [
    ("call_id", "BLOB", false, 1),
    ("prepared_digest", "BLOB", true, 0),
    ("render_digest", "BLOB", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("record_digest", "BLOB", true, 0),
    ("call_digest_version", "INTEGER", true, 0),
];
const PROVIDER_DISPATCH_COLUMNS: [ColumnShape; 13] = [
    ("attempt_id", "BLOB", false, 1),
    ("call_id", "BLOB", true, 0),
    ("permit_id", "BLOB", true, 0),
    ("token_reservation_id", "BLOB", true, 0),
    ("cost_reservation_id", "BLOB", true, 0),
    ("fencing_token", "INTEGER", true, 0),
    ("provider_idempotency_key", "TEXT", true, 0),
    ("prepared_digest", "BLOB", true, 0),
    ("render_digest", "BLOB", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("state", "INTEGER", true, 0),
    ("stream_id", "BLOB", false, 0),
    ("settlement_digest", "BLOB", false, 0),
];
const PROVIDER_DISPATCH_V12_COLUMNS: [ColumnShape; 14] = [
    ("attempt_id", "BLOB", false, 1),
    ("call_id", "BLOB", true, 0),
    ("permit_id", "BLOB", true, 0),
    ("token_reservation_id", "BLOB", true, 0),
    ("cost_reservation_id", "BLOB", true, 0),
    ("fencing_token", "INTEGER", true, 0),
    ("provider_idempotency_key", "TEXT", true, 0),
    ("prepared_digest", "BLOB", true, 0),
    ("render_digest", "BLOB", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("state", "INTEGER", true, 0),
    ("stream_id", "BLOB", false, 0),
    ("settlement_digest", "BLOB", false, 0),
    ("pre_effect_rejection", "INTEGER", false, 0),
];
const PROVIDER_EFFECT_AUTHORITY_COLUMNS: [ColumnShape; 17] = [
    ("authority_id", "BLOB", true, 1),
    ("revision", "INTEGER", true, 2),
    ("attempt_id", "BLOB", true, 0),
    ("permit_id", "BLOB", true, 0),
    ("capability_grant_id", "TEXT", true, 0),
    ("token_reservation_id", "BLOB", true, 0),
    ("cost_reservation_id", "BLOB", true, 0),
    ("prepared_digest", "BLOB", true, 0),
    ("render_digest", "BLOB", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("owner_id", "TEXT", true, 0),
    ("scope", "TEXT", true, 0),
    ("fencing_token", "INTEGER", true, 0),
    ("expires_at", "INTEGER", true, 0),
    ("revoked", "INTEGER", true, 0),
    ("consumed", "INTEGER", true, 0),
    ("consumed_intent_id", "TEXT", false, 0),
];
const SCHEMA_UPGRADE_FENCE_COLUMNS: [ColumnShape; 8] = [
    ("id", "INTEGER", false, 1),
    ("source_version", "INTEGER", true, 0),
    ("target_version", "INTEGER", true, 0),
    ("snapshot_filename", "TEXT", false, 0),
    ("snapshot_digest", "BLOB", false, 0),
    ("baseline_event_next_position", "INTEGER", true, 0),
    ("baseline_provider_prepared_count", "INTEGER", true, 0),
    ("baseline_provider_attempt_count", "INTEGER", true, 0),
];
const SCHEMA_UPGRADE_WRITE_LATCH_COLUMNS: [ColumnShape; 2] =
    [("id", "INTEGER", false, 1), ("closed", "INTEGER", true, 0)];
const PROVIDER_RUNTIME_AUTHORITY_STATE_COLUMNS: [ColumnShape; 28] = [
    ("id", "INTEGER", false, 1),
    ("runtime_authority_id", "BLOB", true, 0),
    ("database_generation", "INTEGER", true, 0),
    ("principal_id", "TEXT", true, 0),
    ("owner_id", "TEXT", true, 0),
    ("scope", "TEXT", true, 0),
    ("expected_generation", "INTEGER", true, 0),
    ("lease_generation", "INTEGER", true, 0),
    ("expected_fencing_token", "INTEGER", true, 0),
    ("lease_fencing_token", "INTEGER", true, 0),
    ("capability_grant_id", "TEXT", true, 0),
    ("capability_revision", "INTEGER", true, 0),
    ("capability_allowed", "INTEGER", true, 0),
    ("approval_id", "TEXT", true, 0),
    ("approval_revision", "INTEGER", true, 0),
    ("approval_allowed", "INTEGER", true, 0),
    ("approval_expires_at", "INTEGER", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("pricing_revision_digest", "BLOB", true, 0),
    ("token_budget_limit", "INTEGER", true, 0),
    ("token_budget_reserved", "INTEGER", true, 0),
    ("token_budget_settled", "INTEGER", true, 0),
    ("cost_budget_limit_micros", "INTEGER", true, 0),
    ("cost_budget_reserved_micros", "INTEGER", true, 0),
    ("cost_budget_settled_micros", "INTEGER", true, 0),
    ("authority_ttl_seconds", "INTEGER", true, 0),
    ("state_revision", "INTEGER", true, 0),
    ("active", "INTEGER", true, 0),
];
const PROVIDER_EXECUTION_ADMISSION_COLUMNS: [ColumnShape; 27] = [
    ("provider_idempotency_key", "TEXT", true, 1),
    ("semantic_digest", "BLOB", true, 0),
    ("principal_id", "TEXT", true, 0),
    ("conversation_id", "BLOB", true, 0),
    ("taskrun_id", "BLOB", true, 0),
    ("execution_attempt_id", "BLOB", true, 0),
    ("call_id", "BLOB", true, 0),
    ("dispatch_attempt_id", "BLOB", true, 0),
    ("authority_id", "BLOB", true, 0),
    ("authority_revision", "INTEGER", true, 0),
    ("permit_id", "BLOB", true, 0),
    ("token_reservation_id", "BLOB", true, 0),
    ("cost_reservation_id", "BLOB", true, 0),
    ("runtime_authority_id", "BLOB", true, 0),
    ("database_generation", "INTEGER", true, 0),
    ("generation", "INTEGER", true, 0),
    ("fencing_token", "INTEGER", true, 0),
    ("prepared_digest", "BLOB", true, 0),
    ("render_digest", "BLOB", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("pricing_revision_digest", "BLOB", true, 0),
    ("requested_input_tokens", "INTEGER", true, 0),
    ("requested_output_tokens", "INTEGER", true, 0),
    ("max_cost_micros", "INTEGER", true, 0),
    ("currency", "TEXT", true, 0),
    ("issued_at", "INTEGER", true, 0),
    ("expires_at", "INTEGER", true, 0),
];
const PROVIDER_BUDGET_RESERVATION_COLUMNS: [ColumnShape; 7] = [
    ("reservation_id", "BLOB", true, 1),
    ("provider_idempotency_key", "TEXT", true, 0),
    ("dimension", "INTEGER", true, 0),
    ("amount", "INTEGER", true, 0),
    ("state", "INTEGER", true, 0),
    ("settled_amount", "INTEGER", false, 0),
    ("released_at", "INTEGER", false, 0),
];
const PROVIDER_JOURNAL_KEY_REF_COLUMNS: [ColumnShape; 8] = [
    ("key_id", "BLOB", true, 1),
    ("key_version", "INTEGER", true, 2),
    ("runtime_authority_id", "BLOB", true, 0),
    ("database_generation", "INTEGER", true, 0),
    ("state", "INTEGER", true, 0),
    ("active_slot", "INTEGER", false, 0),
    ("created_at", "INTEGER", true, 0),
    ("retired_at", "INTEGER", false, 0),
];
const PROVIDER_ENCRYPTION_NONCE_COLUMNS: [ColumnShape; 6] = [
    ("key_id", "BLOB", true, 1),
    ("key_version", "INTEGER", true, 2),
    ("nonce", "BLOB", true, 3),
    ("purpose", "INTEGER", true, 0),
    ("dispatch_attempt_id", "BLOB", true, 0),
    ("sequence", "INTEGER", false, 0),
];
const PROVIDER_POLL_FLIGHT_COLUMNS: [ColumnShape; 5] = [
    ("dispatch_attempt_id", "BLOB", true, 1),
    ("cursor", "INTEGER", true, 0),
    ("runtime_generation", "INTEGER", true, 0),
    ("fencing_token", "INTEGER", true, 0),
    ("opened_at", "INTEGER", true, 0),
];
const PROVIDER_STREAM_JOURNAL_COLUMNS: [ColumnShape; 13] = [
    ("dispatch_attempt_id", "BLOB", true, 1),
    ("sequence", "INTEGER", true, 2),
    ("key_id", "BLOB", true, 0),
    ("key_version", "INTEGER", true, 0),
    ("nonce", "BLOB", true, 0),
    ("call_digest_version", "INTEGER", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("runtime_generation", "INTEGER", true, 0),
    ("event_kind", "INTEGER", true, 0),
    ("terminal", "INTEGER", true, 0),
    ("ciphertext", "BLOB", true, 0),
    ("plaintext_len", "INTEGER", true, 0),
    ("plaintext_digest", "BLOB", true, 0),
];
const PROVIDER_ACCOUNTING_SETTLEMENT_COLUMNS: [ColumnShape; 10] = [
    ("dispatch_attempt_id", "BLOB", true, 1),
    ("pricing_revision_digest", "BLOB", true, 0),
    ("input_tokens", "INTEGER", true, 0),
    ("output_tokens", "INTEGER", true, 0),
    ("cached_input_tokens", "INTEGER", true, 0),
    ("reasoning_output_tokens", "INTEGER", true, 0),
    ("charge_micros", "INTEGER", true, 0),
    ("currency", "TEXT", true, 0),
    ("settlement_digest", "BLOB", true, 0),
    ("committed_at", "INTEGER", true, 0),
];
const PROVIDER_TERMINAL_OUTBOX_COLUMNS: [ColumnShape; 18] = [
    ("outbox_id", "BLOB", true, 1),
    ("dispatch_attempt_id", "BLOB", true, 0),
    ("terminal_sequence", "INTEGER", true, 0),
    ("call_digest_version", "INTEGER", true, 0),
    ("key_id", "BLOB", true, 0),
    ("key_version", "INTEGER", true, 0),
    ("nonce", "BLOB", true, 0),
    ("runtime_generation", "INTEGER", true, 0),
    ("profile_digest", "BLOB", true, 0),
    ("ciphertext", "BLOB", true, 0),
    ("plaintext_len", "INTEGER", true, 0),
    ("plaintext_digest", "BLOB", true, 0),
    ("settlement_digest", "BLOB", true, 0),
    ("application_idempotency_key", "TEXT", true, 0),
    ("state", "INTEGER", true, 0),
    ("receipt_digest", "BLOB", false, 0),
    ("created_at", "INTEGER", true, 0),
    ("applied_at", "INTEGER", false, 0),
];

const CANONICAL_VERIFICATION_EVIDENCE_SQL: &str = "CREATE TABLE verification_evidence (evidence_id BLOB PRIMARY KEY CHECK(length(evidence_id) = 16), run_id BLOB NOT NULL CHECK(length(run_id) = 16), profile_id BLOB NOT NULL CHECK(length(profile_id) = 16), profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32), layer INTEGER NOT NULL CHECK(layer IN (0, 1, 2, 3, 4, 5)), evidence_type INTEGER NOT NULL CHECK(evidence_type IN (0, 1, 2, 3, 4)), evidence_digest BLOB NOT NULL CHECK(length(evidence_digest) = 32), content_ref TEXT NOT NULL CHECK(length(content_ref) > 0), source TEXT NOT NULL CHECK(length(source) > 0), producer_identity TEXT NOT NULL CHECK(length(producer_identity) > 0), sensitivity INTEGER NOT NULL CHECK(sensitivity IN (0, 1, 2)), verified_by TEXT NOT NULL CHECK(length(verified_by) > 0))";
const CANONICAL_CONSUMPTION_INTENTS_SQL: &str = "CREATE TABLE consumption_intents (intent_id BLOB PRIMARY KEY CHECK(length(intent_id) = 16), idempotency_key TEXT NOT NULL UNIQUE CHECK(length(idempotency_key) BETWEEN 1 AND 256), state TEXT NOT NULL CHECK(state IN ('Reserved','Dispatching','Completed','Failed','Invalidated','Abandoned')), gate_head_snapshot_digest BLOB NOT NULL CHECK(length(gate_head_snapshot_digest) = 32), target_artifact_digest BLOB NOT NULL CHECK(length(target_artifact_digest) = 32), integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32))";
const CANONICAL_SCHEMA_LINEAGE_SQL: &str = "CREATE TABLE schema_lineage (schema_version INTEGER PRIMARY KEY CHECK(schema_version = 9), provenance TEXT NOT NULL CHECK(provenance = 'released-v8-to-strict-v9'))";
const CANONICAL_PROVIDER_PREPARED_V12_SQL: &str = "CREATE TABLE provider_prepared_requests (call_id BLOB PRIMARY KEY CHECK(length(call_id) = 16), prepared_digest BLOB NOT NULL CHECK(length(prepared_digest) = 32), render_digest BLOB NOT NULL CHECK(length(render_digest) = 32), profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32), record_digest BLOB NOT NULL CHECK(length(record_digest) = 32), call_digest_version INTEGER NOT NULL DEFAULT 1 CHECK(call_digest_version IN (1, 2)))";

fn v12_upgrade_fence_matches(conn: &Connection) -> SqliteResult<bool> {
    let row = load_v12_upgrade_fence(conn)?;
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM schema_upgrade_fence", [], |row| {
        row.get(0)
    })?;
    let Some(row) = row else {
        return Ok(false);
    };
    let snapshot_pair_matches = match (row.snapshot_filename, row.snapshot_digest) {
        (None, None) => conn.path().is_none_or(str::is_empty),
        (Some(filename), Some(digest)) => safe_snapshot_filename(&filename) && digest.len() == 32,
        _ => false,
    };
    Ok(count == 1
        && row.source_version == 11
        && row.target_version == 12
        && snapshot_pair_matches
        && row.baseline_event_next_position > 0
        && row.baseline_provider_prepared_count >= 0
        && row.baseline_provider_attempt_count >= 0)
}

fn v12_write_latch_matches(conn: &Connection) -> SqliteResult<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_upgrade_write_latch",
        [],
        |row| row.get(0),
    )?;
    let invalid: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM schema_upgrade_write_latch
            WHERE id != 1 OR closed != 1
         )",
        [],
        |row| row.get(0),
    )?;
    Ok(count <= 1 && !invalid)
}

const RELEASED_V12_TABLES: &[&str] = &[
    "_authority",
    "_daemon_info",
    "_replay_subscriptions",
    "aggregate_streams",
    "command_receipts",
    "consumption_intents",
    "cutover_manifests",
    "event_log_state",
    "events",
    "migration_audit",
    "migration_evidence",
    "migration_plans",
    "migration_receipts",
    "migration_reports",
    "migration_transitions",
    "provider_dispatch_attempts",
    "provider_effect_authorities",
    "provider_prepared_requests",
    "retirement_manifests",
    "rollback_manifests",
    "routing_dispatch_intents",
    "routing_head",
    "routing_snapshots",
    "runtime_bindings",
    "schema_lineage",
    "schema_upgrade_fence",
    "schema_upgrade_write_latch",
    "schema_version",
    "security_audit_pre_effect",
    "security_authorization_decisions",
    "security_budget_consumptions",
    "security_dispatch_intents",
    "security_permit_claims",
    "verification_evidence",
];

const RELEASED_V12_EXPLICIT_INDEXES: &[&str] = &[
    "idx_evidence_run",
    "idx_events_aggregate_sequence",
    "idx_migration_evidence_plan",
    "idx_migration_plans_plan_cycle",
    "idx_migration_transitions_plan",
    "idx_receipts_scope_key",
];

fn released_v12_catalog_matches(conn: &Connection) -> SqliteResult<bool> {
    released_catalog_matches(conn, RELEASED_V12_TABLES, RELEASED_V12_EXPLICIT_INDEXES)
}

const RELEASED_V13_TABLES: &[&str] = &[
    "_authority",
    "_daemon_info",
    "_replay_subscriptions",
    "aggregate_streams",
    "command_receipts",
    "consumption_intents",
    "cutover_manifests",
    "event_log_state",
    "events",
    "migration_audit",
    "migration_evidence",
    "migration_plans",
    "migration_receipts",
    "migration_reports",
    "migration_transitions",
    "provider_accounting_settlements",
    "provider_budget_reservations",
    "provider_dispatch_attempts",
    "provider_effect_authorities",
    "provider_encryption_nonces",
    "provider_execution_admissions",
    "provider_journal_key_refs",
    "provider_poll_flights",
    "provider_prepared_requests",
    "provider_runtime_authority_state",
    "provider_stream_journal",
    "provider_terminal_outbox",
    "retirement_manifests",
    "rollback_manifests",
    "routing_dispatch_intents",
    "routing_head",
    "routing_snapshots",
    "runtime_bindings",
    "schema_lineage",
    "schema_upgrade_fence",
    "schema_upgrade_write_latch",
    "schema_version",
    "security_audit_pre_effect",
    "security_authorization_decisions",
    "security_budget_consumptions",
    "security_dispatch_intents",
    "security_permit_claims",
    "verification_evidence",
];

fn released_v13_catalog_matches(conn: &Connection) -> SqliteResult<bool> {
    released_catalog_matches(conn, RELEASED_V13_TABLES, RELEASED_V12_EXPLICIT_INDEXES)
}

fn released_catalog_matches(
    conn: &Connection,
    released_tables: &[&str],
    released_indexes: &[&str],
) -> SqliteResult<bool> {
    let mut tables = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<SqliteResult<Vec<_>>>()?;
    let mut expected_tables = released_tables.to_vec();
    tables.sort();
    expected_tables.sort();
    if tables
        .iter()
        .map(String::as_str)
        .ne(expected_tables.iter().copied())
    {
        return Ok(false);
    }

    let mut explicit_indexes = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'index' AND sql IS NOT NULL
             ORDER BY name",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<SqliteResult<Vec<_>>>()?;
    let mut expected_indexes = released_indexes.to_vec();
    explicit_indexes.sort();
    expected_indexes.sort();
    if explicit_indexes
        .iter()
        .map(String::as_str)
        .ne(expected_indexes.iter().copied())
    {
        return Ok(false);
    }

    let invalid_internal_index: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_master
            WHERE type = 'index'
              AND sql IS NULL
              AND (
                  name NOT LIKE 'sqlite_autoindex_%' OR
                  tbl_name NOT IN (
                      SELECT name FROM sqlite_master
                      WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                  )
              )
         )",
        [],
        |row| row.get(0),
    )?;
    let view_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'view'",
        [],
        |row| row.get(0),
    )?;
    Ok(!invalid_internal_index && view_count == 0)
}

fn table_shape_matches(
    conn: &Connection,
    table: &str,
    expected: &[ColumnShape],
) -> SqliteResult<bool> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info('{table}')"))?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? != 0,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?;
    Ok(actual.len() == expected.len()
        && actual.iter().zip(expected).all(
            |(
                (name, ty, not_null, pk),
                (expected_name, expected_ty, expected_not_null, expected_pk),
            )| {
                name == expected_name
                    && ty == expected_ty
                    && not_null == expected_not_null
                    && pk == expected_pk
            },
        ))
}

fn table_sql_matches(conn: &Connection, table: &str, expected: &str) -> SqliteResult<bool> {
    let actual: Option<String> = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )?;
    Ok(actual.is_some_and(|sql| normalize_sql(&sql) == normalize_sql(expected)))
}

fn table_sql_matches_migration(
    conn: &Connection,
    table: &str,
    migration: &str,
) -> SqliteResult<bool> {
    let ddl: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .optional()?;
    let Some(ddl) = ddl else {
        return Ok(false);
    };
    let expected = migration
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with(&format!("CREATE TABLE {table} ")));
    Ok(expected.is_some_and(|expected| normalize_ddl(&ddl) == normalize_ddl(expected)))
}

fn normalize_ddl(ddl: &str) -> String {
    let mut normalized = String::with_capacity(ddl.len());
    let mut characters = ddl.chars().peekable();
    let mut quoted = false;
    while let Some(character) = characters.next() {
        if quoted {
            normalized.extend(character.to_lowercase());
            if character == '\'' {
                quoted = false;
            }
            continue;
        }
        if character == '\'' {
            quoted = true;
            normalized.push(character);
        } else if character == '-' && characters.peek() == Some(&'-') {
            characters.next();
            while characters.next().is_some_and(|next| next != '\n') {}
        } else if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            while let Some(next) = characters.next() {
                if next == '*' && characters.peek() == Some(&'/') {
                    characters.next();
                    break;
                }
            }
        } else if !character.is_whitespace() {
            normalized.extend(character.to_lowercase());
        }
    }
    normalized
}

fn index_matches(
    conn: &Connection,
    index: &str,
    table: &str,
    columns: &[&str],
) -> SqliteResult<bool> {
    let actual_table: Option<String> = conn
        .query_row(
            "SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?1",
            [index],
            |row| row.get(0),
        )
        .optional()?;
    if actual_table.as_deref() != Some(table) {
        return Ok(false);
    }
    let mut list = conn.prepare(&format!("PRAGMA index_list('{table}')"))?;
    let exact_semantics = list
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? == 0,
                row.get::<_, String>(3)? == "c",
                row.get::<_, i64>(4)? == 0,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?
        .into_iter()
        .any(|(name, non_unique, created, not_partial)| {
            name == index && non_unique && created && not_partial
        });
    if !exact_semantics {
        return Ok(false);
    }
    let mut statement = conn.prepare(&format!("PRAGMA index_xinfo('{index}')"))?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?;
    let key_columns = actual
        .iter()
        .filter(|(_, _, _, _, _, key)| *key != 0)
        .collect::<Vec<_>>();
    Ok(key_columns.len() == columns.len()
        && key_columns.iter().zip(columns).all(
            |((sequence, column_id, name, descending, collation, _), expected)| {
                *sequence >= 0
                    && *column_id >= 0
                    && name.as_deref() == Some(*expected)
                    && *descending == 0
                    && collation == "BINARY"
            },
        ))
}

fn has_candidate_remnant(conn: &Connection) -> SqliteResult<bool> {
    let schema_version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    let mut statement = conn.prepare(
        "SELECT type, name, tbl_name FROM sqlite_master WHERE type IN ('table', 'index', 'trigger', 'view')",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?;
    Ok(objects.iter().any(|(kind, name, table)| {
        let is_candidate_named = name.starts_with("verification_evidence_v")
            || name.starts_with("consumption_intents_v")
            || name.starts_with("schema_lineage_v")
            || name.starts_with("candidate_");
        let targets_owned_table = matches!(
            table.as_str(),
            "verification_evidence" | "consumption_intents" | "schema_lineage"
        );
        let released_v12_fence =
            schema_version >= 12 && kind == "trigger" && name.starts_with("schema_v12_fence_");
        is_candidate_named
            || (targets_owned_table
                && !released_v12_fence
                && !matches!(
                    (kind.as_str(), name.as_str()),
                    ("table", "verification_evidence")
                        | ("table", "consumption_intents")
                        | ("table", "schema_lineage")
                        | ("index", "idx_evidence_run")
                        | ("index", "sqlite_autoindex_consumption_intents_1")
                        | ("index", "sqlite_autoindex_consumption_intents_2")
                        | ("index", "sqlite_autoindex_verification_evidence_1")
                ))
    }))
}

fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace().collect()
}

/// Run startup gates: integrity check, FK check, and PRAGMA profile
/// verification.
///
/// Fails closed (returns an error) if any check fails.
pub fn run_startup_gates(conn: &Connection, _db_path: &str) -> SqliteResult<()> {
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut foreign_key_check = conn.prepare("PRAGMA foreign_key_check")?;
    if foreign_key_check.exists([])? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let schema_version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if schema_version != CURRENT_SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }

    // PRAGMA profile verification
    verify_pragma(conn, "journal_mode", "wal")?;
    verify_pragma(conn, "synchronous", "2")?; // FULL = 2
    verify_pragma(conn, "foreign_keys", "1")?;
    #[cfg(target_os = "macos")]
    verify_pragma(conn, "fullfsync", "1")?;

    // Set file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in &["", "-wal", "-shm"] {
            let path = format!("{}{}", _db_path, suffix);
            if let Ok(meta) = std::fs::metadata(&path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&path, perms)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            }
        }
    }

    Ok(())
}

/// Verify a PRAGMA value matches the expected value.
fn verify_pragma(conn: &Connection, pragma: &str, expected: &str) -> SqliteResult<()> {
    let sql = format!("PRAGMA {};", pragma);
    // PRAGMAs return either text or integer — try integer first, then text
    let actual: String = conn.query_row(&sql, [], |row| {
        row.get::<_, String>(0).or_else(|_| {
            let val: i32 = row.get(0)?;
            Ok(val.to_string())
        })
    })?;
    if actual != expected {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
            Some(format!(
                "PRAGMA {} = '{}', expected '{}'",
                pragma, actual, expected
            )),
        ));
    }
    Ok(())
}

// ── Migration V1: initial schema ─────────────────────────────────────────

const MIGRATION_V1: &str = r#"
CREATE TABLE event_log_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_global_position INTEGER NOT NULL DEFAULT 1
);

INSERT INTO event_log_state (singleton, next_global_position) VALUES (1, 1);

CREATE TABLE task_run_streams (
    taskrun_id BLOB PRIMARY KEY,
    current_version INTEGER NOT NULL DEFAULT 0,
    last_event_id BLOB,
    last_timestamp INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE events (
    event_id BLOB PRIMARY KEY,
    taskrun_id BLOB NOT NULL REFERENCES task_run_streams(taskrun_id),
    sequence INTEGER NOT NULL,
    global_position INTEGER NOT NULL UNIQUE,
    timestamp INTEGER NOT NULL,
    aggregate_type INTEGER NOT NULL,
    sensitivity INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    causation_id BLOB,
    command_id BLOB NOT NULL,
    idempotency_key BLOB NOT NULL,
    actor BLOB NOT NULL,
    payload BLOB NOT NULL,
    integrity_digest BLOB NOT NULL,
    UNIQUE(taskrun_id, sequence)
);

CREATE INDEX idx_events_taskrun_sequence
    ON events(taskrun_id, sequence);

CREATE TABLE command_receipts (
    command_id BLOB NOT NULL,
    idempotency_scope_bytes BLOB NOT NULL,
    idempotency_key BLOB NOT NULL,
    fingerprint BLOB NOT NULL,
    command_outcome BLOB NOT NULL,
    committed_at INTEGER NOT NULL,
    UNIQUE(command_id),
    UNIQUE(idempotency_scope_bytes, idempotency_key)
);

CREATE INDEX idx_receipts_scope_key
    ON command_receipts(idempotency_scope_bytes, idempotency_key);
"#;

// ── Migration V2: correlation_id + aggregate_streams ─────────────────────

const MIGRATION_V2: &str = r#"
ALTER TABLE events ADD COLUMN correlation_id BLOB NOT NULL DEFAULT x'';
ALTER TABLE events ADD COLUMN correlation_type INTEGER NOT NULL DEFAULT 1;
ALTER TABLE events ADD COLUMN integrity_profile INTEGER NOT NULL DEFAULT 1;

ALTER TABLE task_run_streams RENAME TO aggregate_streams;
"#;

// ── Migration V3: typed aggregate stream identity ───────────────────────

const MIGRATION_V3: &str = r#"
CREATE TABLE aggregate_streams_v3 (
    aggregate_type INTEGER NOT NULL CHECK(aggregate_type IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    current_version INTEGER NOT NULL DEFAULT 0 CHECK(current_version >= 0),
    last_event_id BLOB CHECK(last_event_id IS NULL OR length(last_event_id) = 16),
    last_timestamp INTEGER,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(aggregate_type, aggregate_id)
);

INSERT INTO aggregate_streams_v3
    (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
SELECT 1, taskrun_id, current_version, last_event_id, last_timestamp, created_at
FROM aggregate_streams;

CREATE TABLE events_v3 (
    event_id BLOB PRIMARY KEY CHECK(length(event_id) = 16),
    aggregate_type INTEGER NOT NULL CHECK(aggregate_type IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    global_position INTEGER NOT NULL UNIQUE CHECK(global_position > 0),
    timestamp INTEGER NOT NULL,
    sensitivity INTEGER NOT NULL,
    schema_version INTEGER NOT NULL CHECK(schema_version BETWEEN 0 AND 4294967295),
    causation_id BLOB CHECK(causation_id IS NULL OR length(causation_id) = 16),
    command_id BLOB NOT NULL CHECK(length(command_id) = 16),
    idempotency_key BLOB NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    actor BLOB NOT NULL CHECK(length(actor) BETWEEN 1 AND 256),
    payload BLOB NOT NULL,
    integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32),
    correlation_id BLOB NOT NULL CHECK(length(correlation_id) = 16),
    correlation_type INTEGER NOT NULL CHECK(correlation_type IN (1, 2)),
    integrity_profile INTEGER NOT NULL CHECK(integrity_profile IN (1, 2)),
    FOREIGN KEY(aggregate_type, aggregate_id)
        REFERENCES aggregate_streams_v3(aggregate_type, aggregate_id),
    UNIQUE(aggregate_type, aggregate_id, sequence)
);

INSERT INTO events_v3
    (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
     sensitivity, schema_version, causation_id, command_id, idempotency_key,
     actor, payload, integrity_digest, correlation_id, correlation_type,
     integrity_profile)
SELECT event_id, aggregate_type, taskrun_id, sequence, global_position, timestamp,
       sensitivity, schema_version, causation_id, command_id, idempotency_key,
       actor, payload, integrity_digest, correlation_id, correlation_type,
       integrity_profile
FROM events;

DROP TABLE events;
DROP TABLE aggregate_streams;
ALTER TABLE aggregate_streams_v3 RENAME TO aggregate_streams;
ALTER TABLE events_v3 RENAME TO events;

CREATE INDEX idx_events_aggregate_sequence
    ON events(aggregate_type, aggregate_id, sequence);
"#;

// ── Migration V4: migration control plane ───────────────────────────────

const MIGRATION_V4: &str = r#"
CREATE TABLE migration_plans (
    plan_id TEXT PRIMARY KEY CHECK(length(plan_id) BETWEEN 1 AND 128),
    cycle_id TEXT NOT NULL UNIQUE CHECK(length(cycle_id) BETWEEN 1 AND 128),
    cycle_kind INTEGER NOT NULL CHECK(cycle_kind IN (1, 2)),
    parent_cycle_id TEXT CHECK(
        parent_cycle_id IS NULL OR length(parent_cycle_id) BETWEEN 1 AND 128
    ),
    source_generation TEXT NOT NULL CHECK(length(source_generation) BETWEEN 1 AND 128),
    candidate_generation TEXT NOT NULL CHECK(length(candidate_generation) BETWEEN 1 AND 128),
    phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 8),
    status INTEGER NOT NULL CHECK(status IN (1, 2)),
    routing_unit_digest BLOB NOT NULL CHECK(length(routing_unit_digest) = 32),
    gate_policy TEXT NOT NULL CHECK(length(gate_policy) BETWEEN 1 AND 128),
    plan_version INTEGER NOT NULL CHECK(plan_version >= 0),
    created_at INTEGER NOT NULL,
    plan_blob BLOB NOT NULL
);

CREATE TABLE migration_transitions (
    transition_id TEXT PRIMARY KEY CHECK(length(transition_id) BETWEEN 1 AND 128),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    cycle_id TEXT NOT NULL CHECK(length(cycle_id) BETWEEN 1 AND 128),
    from_phase INTEGER NOT NULL CHECK(from_phase BETWEEN 0 AND 8),
    to_phase INTEGER NOT NULL CHECK(to_phase BETWEEN 0 AND 8),
    plan_version INTEGER NOT NULL CHECK(plan_version >= 0),
    occurred_at INTEGER NOT NULL,
    transition_blob BLOB NOT NULL,
    UNIQUE(plan_id, transition_id)
);

CREATE INDEX idx_migration_transitions_plan
    ON migration_transitions(plan_id, plan_version);

CREATE TABLE migration_evidence (
    evidence_digest BLOB PRIMARY KEY CHECK(length(evidence_digest) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    evidence_blob BLOB NOT NULL,
    recorded_at INTEGER NOT NULL,
    UNIQUE(plan_id, evidence_digest)
);

CREATE INDEX idx_migration_evidence_plan
    ON migration_evidence(plan_id);

CREATE TABLE routing_snapshots (
    routing_unit_digest BLOB NOT NULL CHECK(length(routing_unit_digest) = 32),
    routing_generation INTEGER NOT NULL CHECK(routing_generation > 0),
    snapshot_blob BLOB NOT NULL,
    committed_at INTEGER NOT NULL,
    PRIMARY KEY(routing_unit_digest, routing_generation)
);

CREATE TABLE routing_head (
    routing_unit_digest BLOB PRIMARY KEY CHECK(length(routing_unit_digest) = 32),
    routing_generation INTEGER NOT NULL CHECK(routing_generation > 0),
    FOREIGN KEY(routing_unit_digest, routing_generation)
        REFERENCES routing_snapshots(routing_unit_digest, routing_generation)
);

CREATE TABLE runtime_bindings (
    aggregate_type INTEGER NOT NULL CHECK(aggregate_type IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    routing_unit_digest BLOB NOT NULL CHECK(length(routing_unit_digest) = 32),
    routing_generation INTEGER NOT NULL CHECK(routing_generation > 0),
    binding_blob BLOB NOT NULL,
    PRIMARY KEY(aggregate_type, aggregate_id),
    FOREIGN KEY(routing_unit_digest, routing_generation)
        REFERENCES routing_snapshots(routing_unit_digest, routing_generation)
);

CREATE TABLE migration_reports (
    report_id BLOB PRIMARY KEY CHECK(length(report_id) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    report_kind INTEGER NOT NULL CHECK(report_kind BETWEEN 1 AND 255),
    report_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE cutover_manifests (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE rollback_manifests (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    parent_plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE retirement_manifests (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE migration_receipts (
    command_id BLOB PRIMARY KEY CHECK(length(command_id) = 16),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    scope_bytes BLOB NOT NULL CHECK(length(scope_bytes) BETWEEN 1 AND 1024),
    idempotency_key BLOB NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 32),
    outcome_blob BLOB NOT NULL,
    committed_at INTEGER NOT NULL,
    UNIQUE(scope_bytes, idempotency_key)
);

CREATE TABLE migration_audit (
    record_id BLOB PRIMARY KEY CHECK(length(record_id) = 32),
    plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    command_id BLOB NOT NULL CHECK(length(command_id) = 16),
    operator_id TEXT NOT NULL CHECK(length(operator_id) BETWEEN 1 AND 128),
    action INTEGER NOT NULL CHECK(action BETWEEN 1 AND 8),
    recorded_at INTEGER NOT NULL,
    record_blob BLOB NOT NULL,
    UNIQUE(plan_id, command_id)
);
"#;

// ── Migration V5: write-ahead routing dispatch intent ──────────────────

const MIGRATION_V5: &str = r#"
CREATE TABLE routing_dispatch_intents (
    aggregate_type INTEGER NOT NULL CHECK(aggregate_type IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    command_id BLOB NOT NULL UNIQUE CHECK(length(command_id) = 16),
    idempotency_key BLOB NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    dispatch_status INTEGER NOT NULL CHECK(dispatch_status BETWEEN 1 AND 4),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(aggregate_type, aggregate_id),
    FOREIGN KEY(aggregate_type, aggregate_id)
        REFERENCES runtime_bindings(aggregate_type, aggregate_id)
);
"#;

// ── Migration V6: immutable artifact cycle lineage ────────────────────

const MIGRATION_V6: &str = r#"
CREATE UNIQUE INDEX idx_migration_plans_plan_cycle
    ON migration_plans(plan_id, cycle_id);

CREATE TABLE migration_reports_v6 (
    report_id BLOB PRIMARY KEY CHECK(length(report_id) = 32),
    plan_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL CHECK(length(cycle_id) BETWEEN 1 AND 128),
    report_kind INTEGER NOT NULL CHECK(report_kind BETWEEN 1 AND 255),
    report_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(plan_id, cycle_id)
        REFERENCES migration_plans(plan_id, cycle_id)
);

INSERT INTO migration_reports_v6
    (report_id, plan_id, cycle_id, report_kind, report_blob, created_at)
SELECT report_id, reports.plan_id, plans.cycle_id, report_kind, report_blob, reports.created_at
FROM migration_reports AS reports
JOIN migration_plans AS plans ON plans.plan_id = reports.plan_id;

CREATE TABLE cutover_manifests_v6 (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL CHECK(length(cycle_id) BETWEEN 1 AND 128),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(plan_id, cycle_id)
        REFERENCES migration_plans(plan_id, cycle_id)
);

INSERT INTO cutover_manifests_v6
    (manifest_id, plan_id, cycle_id, manifest_blob, created_at)
SELECT manifest_id, manifests.plan_id, plans.cycle_id, manifest_blob, manifests.created_at
FROM cutover_manifests AS manifests
JOIN migration_plans AS plans ON plans.plan_id = manifests.plan_id;

CREATE TABLE rollback_manifests_v6 (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL CHECK(length(cycle_id) BETWEEN 1 AND 128),
    parent_plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(plan_id, cycle_id)
        REFERENCES migration_plans(plan_id, cycle_id)
);

INSERT INTO rollback_manifests_v6
    (manifest_id, plan_id, cycle_id, parent_plan_id, manifest_blob, created_at)
SELECT manifest_id, manifests.plan_id, plans.cycle_id, parent_plan_id,
       manifest_blob, manifests.created_at
FROM rollback_manifests AS manifests
JOIN migration_plans AS plans ON plans.plan_id = manifests.plan_id;

CREATE TABLE retirement_manifests_v6 (
    manifest_id BLOB PRIMARY KEY CHECK(length(manifest_id) = 32),
    plan_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL CHECK(length(cycle_id) BETWEEN 1 AND 128),
    manifest_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(plan_id, cycle_id)
        REFERENCES migration_plans(plan_id, cycle_id)
);

INSERT INTO retirement_manifests_v6
    (manifest_id, plan_id, cycle_id, manifest_blob, created_at)
SELECT manifest_id, manifests.plan_id, plans.cycle_id, manifest_blob, manifests.created_at
FROM retirement_manifests AS manifests
JOIN migration_plans AS plans ON plans.plan_id = manifests.plan_id;

DROP TABLE migration_reports;
DROP TABLE cutover_manifests;
DROP TABLE rollback_manifests;
DROP TABLE retirement_manifests;

ALTER TABLE migration_reports_v6 RENAME TO migration_reports;
ALTER TABLE cutover_manifests_v6 RENAME TO cutover_manifests;
ALTER TABLE rollback_manifests_v6 RENAME TO rollback_manifests;
ALTER TABLE retirement_manifests_v6 RENAME TO retirement_manifests;
"#;

// ── Migration V7: atomic security pre-effect transaction ────────────────

const MIGRATION_V7: &str = r#"
CREATE TABLE security_dispatch_intents (
    intent_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status = 'uncertain')
);

CREATE TABLE security_authorization_decisions (
    intent_id TEXT PRIMARY KEY REFERENCES security_dispatch_intents(intent_id),
    grant_id TEXT NOT NULL,
    allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
    reason TEXT NOT NULL
);

CREATE TABLE security_budget_consumptions (
    intent_id TEXT PRIMARY KEY REFERENCES security_dispatch_intents(intent_id),
    reservation_id TEXT NOT NULL,
    amount INTEGER NOT NULL
);

CREATE TABLE security_audit_pre_effect (
    intent_id TEXT PRIMARY KEY REFERENCES security_dispatch_intents(intent_id),
    side_effect_started INTEGER NOT NULL CHECK (side_effect_started = 1)
);

CREATE TABLE security_permit_claims (
    permit_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL UNIQUE REFERENCES security_dispatch_intents(intent_id)
);
"#;

// ── Migration V8: daemon tables + authority ID ─────────────────────────

const MIGRATION_V8: &str = r#"
CREATE TABLE IF NOT EXISTS _authority (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    authority_id BLOB NOT NULL CHECK (length(authority_id) = 16)
);

CREATE TABLE IF NOT EXISTS _daemon_info (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS _replay_subscriptions (
    session_id BLOB PRIMARY KEY CHECK (length(session_id) = 16),
    principal_id TEXT NOT NULL,
    session_generation INTEGER NOT NULL CHECK (session_generation > 0),
    authority_id BLOB NOT NULL CHECK (length(authority_id) = 16),
    authorization_epoch INTEGER NOT NULL CHECK (authorization_epoch >= 0),
    aggregate_type INTEGER NOT NULL,
    aggregate_id BLOB NOT NULL CHECK (length(aggregate_id) = 16),
    retained_floor INTEGER,
    retention_generation INTEGER NOT NULL CHECK (retention_generation = 0),
    high_water_position INTEGER NOT NULL CHECK (high_water_position >= 0),
    next_page_position INTEGER,
    last_delivered_position INTEGER,
    last_acked_position INTEGER,
    state TEXT NOT NULL CHECK (state IN
      ('catching_up','catch_up_complete','activating_live','live','closed')),
    high_water_ref BLOB NOT NULL,
    catch_up_completion BLOB,
    live_delivery_id BLOB,
    created_at TEXT NOT NULL
);
"#;

// ── Migration V9: strict verification tables from released V8 ───────────

const MIGRATION_V9: &str = r#"
CREATE TABLE verification_evidence (
    evidence_id BLOB PRIMARY KEY CHECK(length(evidence_id) = 16),
    run_id BLOB NOT NULL CHECK(length(run_id) = 16),
    profile_id BLOB NOT NULL CHECK(length(profile_id) = 16),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    layer INTEGER NOT NULL CHECK(layer IN (0, 1, 2, 3, 4, 5)),
    evidence_type INTEGER NOT NULL CHECK(evidence_type IN (0, 1, 2, 3, 4)),
    evidence_digest BLOB NOT NULL CHECK(length(evidence_digest) = 32),
    content_ref TEXT NOT NULL CHECK(length(content_ref) > 0),
    source TEXT NOT NULL CHECK(length(source) > 0),
    producer_identity TEXT NOT NULL CHECK(length(producer_identity) > 0),
    sensitivity INTEGER NOT NULL CHECK(sensitivity IN (0, 1, 2)),
    verified_by TEXT NOT NULL CHECK(length(verified_by) > 0)
);

CREATE INDEX IF NOT EXISTS idx_evidence_run
    ON verification_evidence(run_id);

CREATE TABLE consumption_intents (
    intent_id BLOB PRIMARY KEY CHECK(length(intent_id) = 16),
    idempotency_key TEXT NOT NULL UNIQUE CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    state TEXT NOT NULL CHECK(state IN
        ('Reserved','Dispatching','Completed','Failed',
         'Invalidated','Abandoned')),
    gate_head_snapshot_digest BLOB NOT NULL CHECK(length(gate_head_snapshot_digest) = 32),
    target_artifact_digest BLOB NOT NULL CHECK(length(target_artifact_digest) = 32),
    integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32)
);
CREATE TABLE schema_lineage (
    schema_version INTEGER PRIMARY KEY CHECK(schema_version = 9),
    provenance TEXT NOT NULL CHECK(provenance = 'released-v8-to-strict-v9')
);
INSERT INTO schema_lineage (schema_version, provenance)
    VALUES (9, 'released-v8-to-strict-v9');
"#;

// ── Migration V10: provider prepare/dispatch durability ─────────────────

const MIGRATION_V10: &str = r#"
CREATE TABLE provider_prepared_requests (
    call_id BLOB PRIMARY KEY CHECK(length(call_id) = 16),
    prepared_digest BLOB NOT NULL CHECK(length(prepared_digest) = 32),
    render_digest BLOB NOT NULL CHECK(length(render_digest) = 32),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32)
);

CREATE TABLE provider_dispatch_attempts (
    attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id) = 16),
    call_id BLOB NOT NULL UNIQUE REFERENCES provider_prepared_requests(call_id),
    permit_id BLOB NOT NULL UNIQUE CHECK(length(permit_id) = 16),
    token_reservation_id BLOB NOT NULL CHECK(length(token_reservation_id) = 16),
    cost_reservation_id BLOB NOT NULL CHECK(length(cost_reservation_id) = 16),
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    provider_idempotency_key TEXT NOT NULL UNIQUE
        CHECK(length(provider_idempotency_key) BETWEEN 1 AND 256),
    prepared_digest BLOB NOT NULL CHECK(length(prepared_digest) = 32),
    render_digest BLOB NOT NULL CHECK(length(render_digest) = 32),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    state INTEGER NOT NULL CHECK(state IN (1, 2, 3, 4)),
    stream_id BLOB CHECK(stream_id IS NULL OR length(stream_id) = 16),
    settlement_digest BLOB CHECK(
        settlement_digest IS NULL OR length(settlement_digest) = 32
    )
);
"#;

// ── Migration V11: provider effect authority admission ──────────────────

const MIGRATION_V11: &str = r#"
CREATE TABLE provider_effect_authorities (
    authority_id BLOB NOT NULL CHECK(length(authority_id) = 16 AND authority_id != zeroblob(16)),
    revision INTEGER NOT NULL CHECK(revision > 0),
    attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
    permit_id BLOB NOT NULL CHECK(length(permit_id) = 16),
    capability_grant_id TEXT NOT NULL CHECK(length(capability_grant_id) BETWEEN 1 AND 256),
    token_reservation_id BLOB NOT NULL CHECK(length(token_reservation_id) = 16),
    cost_reservation_id BLOB NOT NULL CHECK(length(cost_reservation_id) = 16),
    prepared_digest BLOB NOT NULL CHECK(length(prepared_digest) = 32),
    render_digest BLOB NOT NULL CHECK(length(render_digest) = 32),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    owner_id TEXT NOT NULL CHECK(length(owner_id) BETWEEN 1 AND 256),
    scope TEXT NOT NULL CHECK(length(scope) BETWEEN 1 AND 256),
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
    consumed INTEGER NOT NULL CHECK(consumed IN (0, 1)),
    consumed_intent_id TEXT UNIQUE,
    PRIMARY KEY(authority_id, revision),
    CHECK((consumed = 0 AND consumed_intent_id IS NULL) OR
          (consumed = 1 AND consumed_intent_id IS NOT NULL))
);
"#;

// ── Migration V12: provider digest and effect lifecycle versioning ──────

const MIGRATION_V12: &str = r#"
ALTER TABLE provider_prepared_requests
    ADD COLUMN call_digest_version INTEGER NOT NULL DEFAULT 1
    CHECK(call_digest_version IN (1, 2));

ALTER TABLE provider_dispatch_attempts
    RENAME TO provider_dispatch_attempts_v10;

CREATE TABLE provider_dispatch_attempts (
    attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id) = 16),
    call_id BLOB NOT NULL UNIQUE REFERENCES provider_prepared_requests(call_id),
    permit_id BLOB NOT NULL UNIQUE CHECK(length(permit_id) = 16),
    token_reservation_id BLOB NOT NULL CHECK(length(token_reservation_id) = 16),
    cost_reservation_id BLOB NOT NULL CHECK(length(cost_reservation_id) = 16),
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    provider_idempotency_key TEXT NOT NULL UNIQUE
        CHECK(length(provider_idempotency_key) BETWEEN 1 AND 256),
    prepared_digest BLOB NOT NULL CHECK(length(prepared_digest) = 32),
    render_digest BLOB NOT NULL CHECK(length(render_digest) = 32),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    state INTEGER NOT NULL CHECK(state IN (1, 2, 3, 4, 5, 6)),
    stream_id BLOB CHECK(stream_id IS NULL OR length(stream_id) = 16),
    settlement_digest BLOB CHECK(
        settlement_digest IS NULL OR length(settlement_digest) = 32
    ),
    pre_effect_rejection INTEGER CHECK(
        pre_effect_rejection IS NULL OR
        pre_effect_rejection IN (1, 2, 3, 4, 5, 6, 7)
    ),
    CHECK(
        (state = 2 AND pre_effect_rejection IS NOT NULL) OR
        (state != 2 AND pre_effect_rejection IS NULL)
    ),
    CHECK(
        (state IN (3, 4) AND stream_id IS NOT NULL) OR
        (state IN (1, 2) AND stream_id IS NULL) OR
        state IN (5, 6)
    ),
    CHECK(
        (state IN (4, 5) AND settlement_digest IS NOT NULL) OR
        (state IN (1, 2, 3) AND settlement_digest IS NULL) OR
        state = 6
    )
);

INSERT INTO provider_dispatch_attempts (
    attempt_id, call_id, permit_id, token_reservation_id,
    cost_reservation_id, fencing_token, provider_idempotency_key,
    prepared_digest, render_digest, profile_digest, state,
    stream_id, settlement_digest, pre_effect_rejection
)
SELECT
    attempt_id, call_id, permit_id, token_reservation_id,
    cost_reservation_id, fencing_token, provider_idempotency_key,
    prepared_digest, render_digest, profile_digest,
    CASE state
        WHEN 1 THEN 1
        WHEN 2 THEN 3
        WHEN 3 THEN 5
        WHEN 4 THEN 6
    END,
    stream_id, settlement_digest, NULL
FROM provider_dispatch_attempts_v10;

DROP TABLE provider_dispatch_attempts_v10;

CREATE TABLE schema_upgrade_fence (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    source_version INTEGER NOT NULL CHECK(source_version = 11),
    target_version INTEGER NOT NULL CHECK(target_version = 12),
    snapshot_filename TEXT,
    snapshot_digest BLOB,
    baseline_event_next_position INTEGER NOT NULL
        CHECK(baseline_event_next_position > 0),
    baseline_provider_prepared_count INTEGER NOT NULL
        CHECK(baseline_provider_prepared_count >= 0),
    baseline_provider_attempt_count INTEGER NOT NULL
        CHECK(baseline_provider_attempt_count >= 0),
    CHECK(
        (snapshot_filename IS NULL AND snapshot_digest IS NULL) OR
        (
            length(snapshot_filename) BETWEEN 1 AND 255 AND
            instr(snapshot_filename, '/') = 0 AND
            instr(snapshot_filename, char(92)) = 0 AND
            length(snapshot_digest) = 32
        )
    )
);

CREATE TABLE schema_upgrade_write_latch (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    closed INTEGER NOT NULL CHECK(closed = 1)
);
"#;

// ── Migration V13: runtime-issued provider authority and encrypted recovery ──

const MIGRATION_V13: &str = r#"
CREATE TABLE provider_runtime_authority_state (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    runtime_authority_id BLOB NOT NULL
        CHECK(length(runtime_authority_id) = 16 AND runtime_authority_id != zeroblob(16)),
    database_generation INTEGER NOT NULL CHECK(database_generation > 0),
    principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
    owner_id TEXT NOT NULL CHECK(length(owner_id) BETWEEN 1 AND 256),
    scope TEXT NOT NULL CHECK(length(scope) BETWEEN 1 AND 256),
    expected_generation INTEGER NOT NULL CHECK(expected_generation > 0),
    lease_generation INTEGER NOT NULL CHECK(lease_generation > 0),
    expected_fencing_token INTEGER NOT NULL CHECK(expected_fencing_token > 0),
    lease_fencing_token INTEGER NOT NULL CHECK(lease_fencing_token > 0),
    capability_grant_id TEXT NOT NULL
        CHECK(length(capability_grant_id) BETWEEN 1 AND 256),
    capability_revision INTEGER NOT NULL CHECK(capability_revision > 0),
    capability_allowed INTEGER NOT NULL CHECK(capability_allowed IN (0, 1)),
    approval_id TEXT NOT NULL CHECK(length(approval_id) BETWEEN 1 AND 256),
    approval_revision INTEGER NOT NULL CHECK(approval_revision > 0),
    approval_allowed INTEGER NOT NULL CHECK(approval_allowed IN (0, 1)),
    approval_expires_at INTEGER NOT NULL,
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    pricing_revision_digest BLOB NOT NULL
        CHECK(length(pricing_revision_digest) = 32),
    token_budget_limit INTEGER NOT NULL CHECK(token_budget_limit >= 0),
    token_budget_reserved INTEGER NOT NULL
        CHECK(token_budget_reserved >= 0 AND token_budget_reserved <= token_budget_limit),
    token_budget_settled INTEGER NOT NULL
        CHECK(
            token_budget_settled >= 0 AND
            token_budget_reserved + token_budget_settled <= token_budget_limit
        ),
    cost_budget_limit_micros INTEGER NOT NULL CHECK(cost_budget_limit_micros >= 0),
    cost_budget_reserved_micros INTEGER NOT NULL
        CHECK(
            cost_budget_reserved_micros >= 0 AND
            cost_budget_reserved_micros <= cost_budget_limit_micros
        ),
    cost_budget_settled_micros INTEGER NOT NULL
        CHECK(
            cost_budget_settled_micros >= 0 AND
            cost_budget_reserved_micros + cost_budget_settled_micros
                <= cost_budget_limit_micros
        ),
    authority_ttl_seconds INTEGER NOT NULL
        CHECK(authority_ttl_seconds BETWEEN 1 AND 300),
    state_revision INTEGER NOT NULL CHECK(state_revision > 0),
    active INTEGER NOT NULL CHECK(active IN (0, 1))
);

CREATE TABLE provider_execution_admissions (
    provider_idempotency_key TEXT NOT NULL PRIMARY KEY
        CHECK(length(provider_idempotency_key) BETWEEN 1 AND 256),
    semantic_digest BLOB NOT NULL CHECK(length(semantic_digest) = 32),
    principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
    conversation_id BLOB NOT NULL CHECK(length(conversation_id) = 16),
    taskrun_id BLOB NOT NULL CHECK(length(taskrun_id) = 16),
    execution_attempt_id BLOB NOT NULL CHECK(length(execution_attempt_id) = 16),
    call_id BLOB NOT NULL UNIQUE
        REFERENCES provider_prepared_requests(call_id),
    dispatch_attempt_id BLOB NOT NULL UNIQUE
        REFERENCES provider_dispatch_attempts(attempt_id),
    authority_id BLOB NOT NULL CHECK(length(authority_id) = 16),
    authority_revision INTEGER NOT NULL CHECK(authority_revision > 0),
    permit_id BLOB NOT NULL UNIQUE CHECK(length(permit_id) = 16),
    token_reservation_id BLOB NOT NULL UNIQUE CHECK(length(token_reservation_id) = 16),
    cost_reservation_id BLOB NOT NULL UNIQUE CHECK(length(cost_reservation_id) = 16),
    runtime_authority_id BLOB NOT NULL CHECK(length(runtime_authority_id) = 16),
    database_generation INTEGER NOT NULL CHECK(database_generation > 0),
    generation INTEGER NOT NULL CHECK(generation > 0),
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    prepared_digest BLOB NOT NULL CHECK(length(prepared_digest) = 32),
    render_digest BLOB NOT NULL CHECK(length(render_digest) = 32),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    pricing_revision_digest BLOB NOT NULL
        CHECK(length(pricing_revision_digest) = 32),
    requested_input_tokens INTEGER NOT NULL CHECK(requested_input_tokens >= 0),
    requested_output_tokens INTEGER NOT NULL CHECK(requested_output_tokens > 0),
    max_cost_micros INTEGER NOT NULL CHECK(max_cost_micros > 0),
    currency TEXT NOT NULL CHECK(length(currency) = 3),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
    FOREIGN KEY(authority_id, authority_revision)
        REFERENCES provider_effect_authorities(authority_id, revision)
);

CREATE TABLE provider_budget_reservations (
    reservation_id BLOB NOT NULL PRIMARY KEY CHECK(length(reservation_id) = 16),
    provider_idempotency_key TEXT NOT NULL
        REFERENCES provider_execution_admissions(provider_idempotency_key),
    dimension INTEGER NOT NULL CHECK(dimension IN (1, 2)),
    amount INTEGER NOT NULL CHECK(amount > 0),
    state INTEGER NOT NULL CHECK(state IN (1, 2)),
    settled_amount INTEGER CHECK(settled_amount IS NULL OR settled_amount >= 0),
    released_at INTEGER,
    UNIQUE(provider_idempotency_key, dimension),
    CHECK(
        (state = 1 AND settled_amount IS NULL AND released_at IS NULL) OR
        (state = 2 AND settled_amount IS NOT NULL AND released_at IS NOT NULL)
    )
);

CREATE TABLE provider_journal_key_refs (
    key_id BLOB NOT NULL CHECK(length(key_id) = 16 AND key_id != zeroblob(16)),
    key_version INTEGER NOT NULL CHECK(key_version > 0),
    runtime_authority_id BLOB NOT NULL CHECK(length(runtime_authority_id) = 16),
    database_generation INTEGER NOT NULL CHECK(database_generation > 0),
    state INTEGER NOT NULL CHECK(state IN (1, 2)),
    active_slot INTEGER UNIQUE CHECK(active_slot IS NULL OR active_slot = 1),
    created_at INTEGER NOT NULL,
    retired_at INTEGER,
    PRIMARY KEY(key_id, key_version),
    CHECK(
        (state = 1 AND active_slot = 1 AND retired_at IS NULL) OR
        (state = 2 AND active_slot IS NULL AND retired_at IS NOT NULL)
    )
);

CREATE TABLE provider_encryption_nonces (
    key_id BLOB NOT NULL,
    key_version INTEGER NOT NULL,
    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
    purpose INTEGER NOT NULL CHECK(purpose IN (1, 2)),
    dispatch_attempt_id BLOB NOT NULL
        REFERENCES provider_dispatch_attempts(attempt_id),
    sequence INTEGER CHECK(sequence IS NULL OR sequence >= 0),
    PRIMARY KEY(key_id, key_version, nonce),
    FOREIGN KEY(key_id, key_version)
        REFERENCES provider_journal_key_refs(key_id, key_version),
    CHECK(
        (purpose = 1 AND sequence IS NOT NULL) OR
        (purpose = 2 AND sequence IS NULL)
    )
);

CREATE TABLE provider_poll_flights (
    dispatch_attempt_id BLOB NOT NULL PRIMARY KEY
        REFERENCES provider_dispatch_attempts(attempt_id),
    cursor INTEGER NOT NULL CHECK(cursor >= 0),
    runtime_generation INTEGER NOT NULL CHECK(runtime_generation > 0),
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    opened_at INTEGER NOT NULL
);

CREATE TABLE provider_stream_journal (
    dispatch_attempt_id BLOB NOT NULL
        REFERENCES provider_dispatch_attempts(attempt_id),
    sequence INTEGER NOT NULL CHECK(sequence >= 0),
    key_id BLOB NOT NULL,
    key_version INTEGER NOT NULL,
    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
    call_digest_version INTEGER NOT NULL CHECK(call_digest_version IN (1, 2)),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    runtime_generation INTEGER NOT NULL CHECK(runtime_generation > 0),
    event_kind INTEGER NOT NULL CHECK(event_kind BETWEEN 1 AND 7),
    terminal INTEGER NOT NULL CHECK(terminal IN (0, 1)),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 2097152),
    plaintext_len INTEGER NOT NULL CHECK(plaintext_len >= 0),
    plaintext_digest BLOB NOT NULL CHECK(length(plaintext_digest) = 32),
    PRIMARY KEY(dispatch_attempt_id, sequence),
    FOREIGN KEY(key_id, key_version, nonce)
        REFERENCES provider_encryption_nonces(key_id, key_version, nonce)
);

CREATE TABLE provider_accounting_settlements (
    dispatch_attempt_id BLOB NOT NULL PRIMARY KEY
        REFERENCES provider_dispatch_attempts(attempt_id),
    pricing_revision_digest BLOB NOT NULL
        CHECK(length(pricing_revision_digest) = 32),
    input_tokens INTEGER NOT NULL CHECK(input_tokens >= 0),
    output_tokens INTEGER NOT NULL CHECK(output_tokens >= 0),
    cached_input_tokens INTEGER NOT NULL
        CHECK(cached_input_tokens >= 0 AND cached_input_tokens <= input_tokens),
    reasoning_output_tokens INTEGER NOT NULL
        CHECK(reasoning_output_tokens >= 0 AND reasoning_output_tokens <= output_tokens),
    charge_micros INTEGER NOT NULL CHECK(charge_micros >= 0),
    currency TEXT NOT NULL CHECK(length(currency) = 3),
    settlement_digest BLOB NOT NULL UNIQUE CHECK(length(settlement_digest) = 32),
    committed_at INTEGER NOT NULL
);

CREATE TABLE provider_terminal_outbox (
    outbox_id BLOB NOT NULL PRIMARY KEY CHECK(length(outbox_id) = 16),
    dispatch_attempt_id BLOB NOT NULL UNIQUE
        REFERENCES provider_dispatch_attempts(attempt_id),
    terminal_sequence INTEGER NOT NULL CHECK(terminal_sequence >= 0),
    call_digest_version INTEGER NOT NULL CHECK(call_digest_version IN (1, 2)),
    key_id BLOB NOT NULL,
    key_version INTEGER NOT NULL,
    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
    runtime_generation INTEGER NOT NULL CHECK(runtime_generation > 0),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 4194304),
    plaintext_len INTEGER NOT NULL CHECK(plaintext_len >= 0),
    plaintext_digest BLOB NOT NULL CHECK(length(plaintext_digest) = 32),
    settlement_digest BLOB NOT NULL CHECK(length(settlement_digest) = 32),
    application_idempotency_key TEXT NOT NULL UNIQUE
        CHECK(length(application_idempotency_key) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK(state IN (1, 2)),
    receipt_digest BLOB CHECK(receipt_digest IS NULL OR length(receipt_digest) = 32),
    created_at INTEGER NOT NULL,
    applied_at INTEGER,
    FOREIGN KEY(key_id, key_version, nonce)
        REFERENCES provider_encryption_nonces(key_id, key_version, nonce),
    CHECK(
        (state = 1 AND receipt_digest IS NULL AND applied_at IS NULL) OR
        (state = 2 AND receipt_digest IS NOT NULL AND applied_at IS NOT NULL)
    )
);
"#;

/// Open a database connection with the standard set of PRAGMAs.
pub fn open_with_pragmas(db_path: &str) -> SqliteResult<Connection> {
    let is_memory = db_path == ":memory:";
    let path = Path::new(db_path);
    let is_new_file = !is_memory && !path.exists();
    if !is_memory && !path_is_safe(path) {
        return Err(diagnostic_error(SchemaOpenDiagnostic::UnsafePath));
    }
    if !is_memory && !is_new_file {
        preflight_existing_file(path)?;
    }
    if is_new_file {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => drop(file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A competing creator won the race. Treat its file as existing
                // and never initialise it through this caller.
                return Err(diagnostic_error(
                    SchemaOpenDiagnostic::FileIdentityUncertain,
                ));
            }
            Err(error) => return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(error))),
        }
    }
    let conn = Connection::open(db_path)?;

    if is_new_file {
        #[cfg(unix)]
        secure_file_permissions(path)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    }

    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;

    // macOS-specific: fullfsync
    #[cfg(target_os = "macos")]
    {
        conn.execute_batch("PRAGMA fullfsync = ON;")?;
    }

    // WAL sidecars are created by the PRAGMA above. Secure them before this
    // newly created database is returned for writable migrations.
    if is_new_file {
        #[cfg(unix)]
        for suffix in ["-wal", "-shm"] {
            let sidecar = sidecar_path(path, suffix);
            if sidecar.exists() {
                secure_file_permissions(&sidecar)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            }
        }
    }

    if !is_memory {
        admit_identity(path).map_err(diagnostic_error)?;
    }

    Ok(conn)
}

// ── Authority ID ────────────────────────────────────────────────────────

/// Generate a new random authority ID.
pub fn generate_authority_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

/// Read the authority ID from the database.
/// Returns None if no row exists.
pub fn read_authority_id(conn: &Connection) -> SqliteResult<Option<[u8; 16]>> {
    let mut stmt = conn.prepare("SELECT authority_id FROM _authority WHERE id = 1")?;
    let mut rows = stmt.query([])?;
    match rows.next()? {
        Some(row) => {
            let blob: Vec<u8> = row.get(0)?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&blob);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

/// Insert authority ID (only if no row exists — idempotent).
pub fn ensure_authority_id(conn: &Connection, authority_id: &[u8; 16]) -> SqliteResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO _authority (id, authority_id) VALUES (1, ?1)",
        rusqlite::params![authority_id.as_slice()],
    )?;
    Ok(())
}

/// Returns the durable UUIDv7 identity of the current Event Log lineage,
/// creating it once for a newly initialized database.
pub fn ensure_event_log_lineage_id(conn: &Connection) -> SqliteResult<EventLogLineageId> {
    const KEY: &str = "event_log_lineage_id";

    conn.execute(
        "INSERT OR IGNORE INTO _daemon_info (key, value) VALUES (?1, ?2)",
        (KEY, uuid::Uuid::now_v7().to_string()),
    )?;
    let value: String = conn.query_row(
        "SELECT value FROM _daemon_info WHERE key = ?1",
        [KEY],
        |row| row.get(0),
    )?;
    value.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

/// Reads the existing Event Log lineage without creating or rewriting it.
pub fn read_event_log_lineage_id(conn: &Connection) -> SqliteResult<Option<EventLogLineageId>> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = 'event_log_lineage_id'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| {
            value.parse().map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

/// Creates or verifies the exact prepared first-activation lineage.
pub fn ensure_exact_event_log_lineage_id(
    conn: &Connection,
    expected: EventLogLineageId,
) -> SqliteResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO _daemon_info (key, value)
         VALUES ('event_log_lineage_id', ?1)",
        [expected.to_string()],
    )?;
    if read_event_log_lineage_id(conn)? == Some(expected) {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

/// Creates or verifies the exact durable first-activation preparation ID.
pub fn ensure_exact_first_activation_preparation(
    conn: &Connection,
    preparation_id: &[u8; 16],
) -> SqliteResult<()> {
    if validate_uuid_v7_bytes(preparation_id).is_err() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let expected = uuid::Uuid::from_bytes(*preparation_id).to_string();
    conn.execute(
        "INSERT OR IGNORE INTO _daemon_info (key, value)
         VALUES ('protected_first_activation_preparation_v1', ?1)",
        [&expected],
    )?;
    let actual: String = conn.query_row(
        "SELECT value FROM _daemon_info
         WHERE key = 'protected_first_activation_preparation_v1'",
        [],
        |row| row.get(0),
    )?;
    if actual == expected {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

/// Reads the durable first-activation preparation identity without mutation.
pub fn read_first_activation_preparation(conn: &Connection) -> SqliteResult<Option<[u8; 16]>> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM _daemon_info
             WHERE key = 'protected_first_activation_preparation_v1'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| {
            let parsed = uuid::Uuid::parse_str(&value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            let bytes = *parsed.as_bytes();
            validate_uuid_v7_bytes(&bytes).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok(bytes)
        })
        .transpose()
}

/// Read-only classification for a committed or safely resumable first activation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FirstActivationResumeState {
    /// Exact identity is durable and at least one protected launch completed.
    Prepared,
    /// Exact identity is durable, but sidecar provisioning did not yet reach
    /// launch-authority consumption or generation allocation.
    RecoverablePrepared,
    /// Migrations may have created the file, but no launch was consumed or run.
    RecoverablePartial,
}

/// Atomically creates or verifies the complete prepared first-activation identity.
pub fn ensure_exact_first_activation_identity(
    conn: &Connection,
    authority_id: &[u8; 16],
    lineage_id: EventLogLineageId,
    preparation_id: &[u8; 16],
) -> SqliteResult<()> {
    validate_uuid_v7_bytes(authority_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    validate_uuid_v7_bytes(preparation_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| {
        ensure_authority_id(conn, authority_id)?;
        ensure_exact_event_log_lineage_id(conn, lineage_id)?;
        ensure_exact_first_activation_preparation(conn, preparation_id)?;
        if read_authority_id(conn)? != Some(*authority_id)
            || read_event_log_lineage_id(conn)? != Some(lineage_id)
            || read_first_activation_preparation(conn)? != Some(*preparation_id)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(())
    })();
    match result {
        Ok(()) => conn.execute_batch("COMMIT"),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

/// Classifies an existing database before resuming an exact prepared activation.
///
/// A partial database is recoverable only before any launch generation or
/// protected launch authority has been persisted, and only when its authority
/// is absent or already equals the signed prepared authority.
pub fn preflight_first_activation_resume(
    conn: &Connection,
    authority_id: &[u8; 16],
    lineage_id: EventLogLineageId,
    preparation_id: &[u8; 16],
) -> SqliteResult<FirstActivationResumeState> {
    validate_uuid_v7_bytes(authority_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    validate_uuid_v7_bytes(preparation_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let authority = read_authority_id(conn)?;
    let lineage = read_event_log_lineage_id(conn)?;
    let preparation = read_first_activation_preparation(conn)?;
    let launch_generation: Option<String> = conn
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = 'launch_generation'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let consumed_authorities: i64 = conn.query_row(
        "SELECT COUNT(*) FROM _daemon_info
         WHERE key LIKE 'protected_launch_authority_v1:%'",
        [],
        |row| row.get(0),
    )?;
    if authority == Some(*authority_id)
        && lineage == Some(lineage_id)
        && preparation == Some(*preparation_id)
    {
        return match (launch_generation.is_some(), consumed_authorities > 0) {
            (true, true) => Ok(FirstActivationResumeState::Prepared),
            (false, false) => Ok(FirstActivationResumeState::RecoverablePrepared),
            _ => Err(rusqlite::Error::InvalidQuery),
        };
    }
    if authority.is_none_or(|actual| actual == *authority_id)
        && lineage.is_none()
        && preparation.is_none()
        && launch_generation.is_none()
        && consumed_authorities == 0
    {
        return Ok(FirstActivationResumeState::RecoverablePartial);
    }
    Err(rusqlite::Error::InvalidQuery)
}

/// Closed result of durably consuming one protected launch authority.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LaunchAuthorityConsumptionError {
    /// The same non-secret authority identity was already consumed.
    AlreadyConsumed,
    /// The authority identity is not a UUIDv7.
    InvalidAuthority,
    /// SQLite could not atomically persist the consumption record.
    Storage,
}

impl fmt::Display for LaunchAuthorityConsumptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyConsumed => "launch authority already consumed",
            Self::InvalidAuthority => "launch authority is invalid",
            Self::Storage => "launch authority storage unavailable",
        })
    }
}

impl std::error::Error for LaunchAuthorityConsumptionError {}

/// Atomically consumes a non-secret launch-authority identity.
///
/// The durable marker is inserted under `BEGIN IMMEDIATE` and is never
/// removed. Callers must complete this before allocating a launch generation.
pub fn consume_protected_launch_authority(
    conn: &Connection,
    launch_authority_id: &[u8; 16],
) -> Result<(), LaunchAuthorityConsumptionError> {
    if validate_uuid_v7_bytes(launch_authority_id).is_err() {
        return Err(LaunchAuthorityConsumptionError::InvalidAuthority);
    }
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|_| LaunchAuthorityConsumptionError::Storage)?;
    let key = format!(
        "protected_launch_authority_v1:{}",
        uuid::Uuid::from_bytes(*launch_authority_id)
    );
    let result = conn.execute(
        "INSERT OR IGNORE INTO _daemon_info (key, value) VALUES (?1, 'consumed')",
        [key],
    );
    match result {
        Ok(1) => conn
            .execute_batch("COMMIT")
            .map_err(|_| LaunchAuthorityConsumptionError::Storage),
        Ok(0) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(LaunchAuthorityConsumptionError::AlreadyConsumed)
        }
        Ok(_) | Err(_) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(LaunchAuthorityConsumptionError::Storage)
        }
    }
}

/// Allocates the next durable positive daemon launch generation.
///
/// The read, validation, increment, and write occur under one `BEGIN
/// IMMEDIATE` transaction. Corrupt state is never rewritten.
pub fn next_launch_generation(conn: &Connection) -> SqliteResult<u64> {
    const KEY: &str = "launch_generation";
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| {
        let current: Option<String> = conn
            .query_row(
                "SELECT value FROM _daemon_info WHERE key = ?1",
                [KEY],
                |row| row.get(0),
            )
            .optional()?;
        let generation = match current {
            None => 1,
            Some(value) => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| launch_generation_corruption())?;
                if parsed == 0 || parsed.to_string() != value {
                    return Err(launch_generation_corruption());
                }
                parsed
                    .checked_add(1)
                    .ok_or_else(launch_generation_corruption)?
            }
        };
        conn.execute(
            "INSERT INTO _daemon_info (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (KEY, generation.to_string()),
        )?;
        Ok(generation)
    })();
    match result {
        Ok(generation) => {
            conn.execute_batch("COMMIT")?;
            Ok(generation)
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn launch_generation_corruption() -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "corrupt launch generation",
    )))
}

// ── Startup purge ───────────────────────────────────────────────────────

/// Purge stale replay subscriptions at startup.
pub fn purge_replay_subscriptions(conn: &Connection) -> SqliteResult<()> {
    conn.execute("DELETE FROM _replay_subscriptions", [])?;
    Ok(())
}

// ── Platform-specific file ACL ──────────────────────────────────────────

/// Platform-specific file ACL (Windows: private DACL, Unix: 0600).
#[cfg(unix)]
pub fn secure_file_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
pub fn secure_file_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    // Windows ACL is handled during file creation in lock.rs
    Ok(())
}

/// Protect parent directory: 0700 (Unix) / private DACL (Windows).
#[cfg(unix)]
pub fn secure_dir_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
pub fn secure_dir_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    const TEST_ID: [u8; 16] = [0x42; 16];

    fn initialize_v1(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .unwrap();
        conn.execute_batch(MIGRATION_V1).unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .unwrap();
    }

    #[test]
    fn immutable_preflight_does_not_create_wal_sidecars() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("event log.db");
        let connection = Connection::open(&path).unwrap();
        apply_migrations(&connection).unwrap();
        drop(connection);
        assert!(!sidecar_path(&path, "-wal").exists());
        assert!(!sidecar_path(&path, "-shm").exists());

        preflight_existing_file(&path).unwrap();
        preflight_existing_file(&path).unwrap();
        drop(open_existing_read_only(&path).unwrap());

        assert!(!sidecar_path(&path, "-wal").exists());
        assert!(!sidecar_path(&path, "-shm").exists());
    }

    #[cfg(unix)]
    #[test]
    fn protected_recovery_admits_only_an_exact_owner_private_hot_wal_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime_root = temporary.path().join("runtime");
        let daemon_dir = runtime_root.join("gocode-daemon");
        fs::create_dir_all(&daemon_dir).unwrap();
        fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&daemon_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = daemon_dir.join("event-log.db");
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
        apply_migrations(&writer).unwrap();
        let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        reader
            .execute_batch("BEGIN; SELECT * FROM schema_version;")
            .unwrap();
        writer
            .execute(
                "INSERT INTO _daemon_info (key, value) VALUES ('protected-test-hot-wal', '1')",
                [],
            )
            .unwrap();
        for file in [
            path.clone(),
            sidecar_path(&path, "-wal"),
            sidecar_path(&path, "-shm"),
        ] {
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(preflight_existing_file(&path).is_err());
        assert!(
            with_protected_recovery_read_only_admission(&path, |_| {
                Err(rusqlite::Error::InvalidQuery)
            })
            .is_err()
        );
        assert!(preflight_existing_file(&path).is_err());

        with_protected_recovery_read_only_admission(&path, |connection| {
            let value: String = connection.query_row(
                "SELECT value FROM _daemon_info WHERE key = 'protected-test-hot-wal'",
                [],
                |row| row.get(0),
            )?;
            if value == "1" {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        })
        .unwrap();
        preflight_existing_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn protected_recovery_rejects_non_private_or_linked_file_sets() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime_root = temporary.path().join("runtime");
        let daemon_dir = runtime_root.join("gocode-daemon");
        fs::create_dir_all(&daemon_dir).unwrap();
        fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&daemon_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = daemon_dir.join("event-log.db");
        fs::write(&path, [1]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let unrelated = daemon_dir.join("unrelated");
        fs::write(&unrelated, [2]).unwrap();
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&unrelated, sidecar_path(&path, "-wal")).unwrap();

        assert!(
            with_protected_recovery_read_only_admission(&path, |_| Ok(())).is_err(),
            "a linked WAL must fail before SQLite admission"
        );
        fs::remove_file(sidecar_path(&path, "-wal")).unwrap();
        std::os::unix::fs::symlink(daemon_dir.join("missing"), sidecar_path(&path, "-wal"))
            .unwrap();
        fs::write(sidecar_path(&path, "-shm"), [4]).unwrap();
        fs::set_permissions(
            sidecar_path(&path, "-shm"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(
            with_protected_recovery_read_only_admission(&path, |_| Ok(())).is_err(),
            "a dangling sidecar link must fail before SQLite admission"
        );
        fs::remove_file(sidecar_path(&path, "-wal")).unwrap();
        fs::remove_file(sidecar_path(&path, "-shm")).unwrap();
        fs::write(sidecar_path(&path, "-wal"), [3]).unwrap();
        fs::set_permissions(
            sidecar_path(&path, "-wal"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            with_protected_recovery_read_only_admission(&path, |_| Ok(())).is_err(),
            "a group/world-readable WAL must fail before SQLite admission"
        );
    }

    #[cfg(unix)]
    #[test]
    fn admitted_database_identity_does_not_follow_path_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("event-log.db");
        fs::write(&path, [1]).unwrap();
        admit_identity(&path).unwrap();
        assert!(identity_is_admitted(&path).unwrap());

        fs::rename(&path, temporary.path().join("original.db")).unwrap();
        fs::write(&path, [2]).unwrap();
        assert!(
            !identity_is_admitted(&path).unwrap(),
            "admission must bind the file identity, not only its path"
        );
    }

    #[test]
    fn migrations_backfill_v1_event_without_changing_durable_identity() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_v1(&conn);
        conn.execute(
            "INSERT INTO task_run_streams
             (taskrun_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (?1, 1, ?1, 0, 0)",
            params![TEST_ID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events
             (event_id, taskrun_id, sequence, global_position, timestamp,
              aggregate_type, sensitivity, schema_version, causation_id,
              command_id, idempotency_key, actor, payload, integrity_digest)
             VALUES (?1, ?1, 1, 1, 0, 1, 0, 1, NULL, ?1, x'01', x'02', x'03', zeroblob(32))",
            params![TEST_ID],
        )
        .unwrap();

        apply_migrations(&conn).unwrap();

        let (
            aggregate_id,
            correlation_id,
            correlation_type,
            integrity_profile,
            global_position,
            integrity_digest,
        ): (Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>) = conn
            .query_row(
                "SELECT aggregate_id, correlation_id, correlation_type, integrity_profile,
                        global_position, integrity_digest
                 FROM events",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(aggregate_id, TEST_ID);
        assert_eq!(correlation_id, TEST_ID);
        assert_eq!(correlation_type, 1);
        assert_eq!(integrity_profile, 1);
        assert_eq!(global_position, 1);
        assert_eq!(integrity_digest, vec![0; 32]);

        let stream_type: i64 = conn
            .query_row(
                "SELECT aggregate_type FROM aggregate_streams WHERE aggregate_id = ?1",
                params![TEST_ID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stream_type, 1);
    }

    #[test]
    fn test_failed_v2_migration_rolls_back_and_can_retry() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_v1(&conn);
        conn.execute_batch("CREATE TABLE aggregate_streams (taskrun_id BLOB PRIMARY KEY)")
            .unwrap();

        assert!(apply_migrations(&conn).is_err());

        let version: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 1);
        let correlation_column_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'correlation_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(correlation_column_count, 0);

        conn.execute_batch("DROP TABLE aggregate_streams").unwrap();
        apply_migrations(&conn).unwrap();

        let version: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'aggregate_streams'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_count, 1);
    }

    #[test]
    fn schema_v6_adds_migration_tables_with_cycle_lineage_atomically() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migrations(&conn).unwrap();

        assert_eq!(CURRENT_SCHEMA_VERSION, 13);
        for table in [
            "migration_plans",
            "migration_transitions",
            "migration_evidence",
            "routing_snapshots",
            "routing_head",
            "runtime_bindings",
            "routing_dispatch_intents",
            "migration_reports",
            "cutover_manifests",
            "rollback_manifests",
            "retirement_manifests",
            "migration_receipts",
            "migration_audit",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "missing migration table {table}");
        }
        for table in [
            "migration_reports",
            "cutover_manifests",
            "rollback_manifests",
            "retirement_manifests",
        ] {
            let cycle_column_count: i64 = conn
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = 'cycle_id'"
                    ),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(cycle_column_count, 1, "missing cycle lineage on {table}");
        }
    }

    #[test]
    fn schema_v7_adds_atomic_pre_effect_tables_together() {
        let conn = Connection::open_in_memory().unwrap();
        apply_migrations(&conn).unwrap();

        for table in [
            "security_dispatch_intents",
            "security_authorization_decisions",
            "security_budget_consumptions",
            "security_audit_pre_effect",
            "security_permit_claims",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "missing atomic pre-effect table {table}");
        }
    }

    #[test]
    fn schema_v6_backfills_existing_artifacts_without_changing_identity_or_bytes() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE migration_plans (
                 plan_id TEXT PRIMARY KEY,
                 cycle_id TEXT NOT NULL UNIQUE
             );
             INSERT INTO migration_plans VALUES ('plan-1', 'cycle-1');
             INSERT INTO migration_plans VALUES ('parent-1', 'parent-cycle-1');
             CREATE TABLE migration_reports (
                 report_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 report_kind INTEGER NOT NULL,
                 report_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE cutover_manifests (
                 manifest_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 manifest_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE rollback_manifests (
                 manifest_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 parent_plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 manifest_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE retirement_manifests (
                 manifest_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 manifest_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             INSERT INTO migration_reports VALUES (zeroblob(32), 'plan-1', 1, x'0102', 10);
             INSERT INTO cutover_manifests VALUES (randomblob(32), 'plan-1', x'0304', 11);
             INSERT INTO rollback_manifests
                 VALUES (randomblob(32), 'plan-1', 'parent-1', x'0506', 12);
             INSERT INTO retirement_manifests VALUES (randomblob(32), 'plan-1', x'0708', 13);",
        )
        .unwrap();

        conn.execute_batch(MIGRATION_V6).unwrap();

        for (table, expected_blob) in [
            ("migration_reports", vec![1_u8, 2]),
            ("cutover_manifests", vec![3_u8, 4]),
            ("rollback_manifests", vec![5_u8, 6]),
            ("retirement_manifests", vec![7_u8, 8]),
        ] {
            let (cycle_id, blob): (String, Vec<u8>) = conn
                .query_row(
                    &format!(
                        "SELECT cycle_id, {}_blob FROM {table}",
                        artifact_blob_prefix(table)
                    ),
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(cycle_id, "cycle-1");
            assert_eq!(blob, expected_blob);
        }
        let mut foreign_key_check = conn.prepare("PRAGMA foreign_key_check").unwrap();
        assert!(!foreign_key_check.exists([]).unwrap());
    }

    fn initialize_released_v8(conn: &Connection) {
        initialize_v1(conn);
        let tx = conn.unchecked_transaction().unwrap();
        tx.execute_batch(MIGRATION_V2).unwrap();
        tx.execute("UPDATE events SET correlation_id = taskrun_id, correlation_type = 1, integrity_profile = 1", []).unwrap();
        tx.execute("INSERT INTO schema_version (version) VALUES (2)", [])
            .unwrap();
        tx.commit().unwrap();
        for (version, migration) in [
            (3, MIGRATION_V3),
            (4, MIGRATION_V4),
            (5, MIGRATION_V5),
            (6, MIGRATION_V6),
            (7, MIGRATION_V7),
            (8, MIGRATION_V8),
        ] {
            let tx = conn.unchecked_transaction().unwrap();
            tx.execute_batch(migration).unwrap();
            tx.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [version],
            )
            .unwrap();
            tx.commit().unwrap();
        }
    }

    fn initialize_released_v11(conn: &Connection) {
        initialize_released_v8(conn);
        for (version, migration) in [(9, MIGRATION_V9), (10, MIGRATION_V10), (11, MIGRATION_V11)] {
            let tx = conn.unchecked_transaction().unwrap();
            tx.execute_batch(migration).unwrap();
            tx.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [version],
            )
            .unwrap();
            tx.commit().unwrap();
        }
    }

    #[test]
    fn durable_v11_upgrade_creates_exact_snapshot_but_blocks_in_place_rollback() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("authoritative.sqlite");
        let connection = Connection::open(&path).unwrap();
        initialize_released_v11(&connection);
        connection
            .execute(
                "INSERT INTO _daemon_info (key, value) VALUES ('v11-sentinel', 'preserved')",
                [],
            )
            .unwrap();

        apply_migrations_through(&connection, 12, None).unwrap();

        let snapshot_filename: String = connection
            .query_row(
                "SELECT snapshot_filename FROM schema_upgrade_fence WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!v12_write_latch_closed(&connection).unwrap());
        let snapshot_path = temporary.path().join(snapshot_filename);
        assert!(snapshot_path.is_file());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&snapshot_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let snapshot =
            Connection::open_with_flags(&snapshot_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(
            snapshot
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            11
        );
        assert_eq!(
            snapshot
                .query_row(
                    "SELECT value FROM _daemon_info WHERE key = 'v11-sentinel'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "preserved"
        );
        drop(snapshot);
        drop(connection);

        assert_eq!(
            rollback_pre_v12_snapshot(&path),
            Err(SchemaRollbackError::AuthoritySwitchUnavailable)
        );

        let unchanged =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(
            unchanged
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            12
        );
        assert_eq!(
            unchanged
                .query_row(
                    "SELECT value FROM _daemon_info WHERE key = 'v11-sentinel'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "preserved"
        );
        assert!(
            unchanged
                .prepare("SELECT call_digest_version FROM provider_prepared_requests")
                .is_ok()
        );
    }

    #[test]
    fn every_v12_authoritative_table_is_fenced_and_postwrite_rollback_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("authoritative.sqlite");
        let connection = Connection::open(&path).unwrap();
        initialize_released_v11(&connection);
        apply_migrations_through(&connection, 12, None).unwrap();

        let authoritative_tables = connection
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table'
                   AND name NOT LIKE 'sqlite_%'
                   AND name NOT IN (
                       'schema_version',
                       'schema_upgrade_fence',
                       'schema_upgrade_write_latch'
                   )
                 ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<SqliteResult<Vec<_>>>()
            .unwrap();
        for table in &authoritative_tables {
            for suffix in ["insert", "update", "delete"] {
                let trigger = format!("schema_v12_fence_{table}_{suffix}");
                let exists: bool = connection
                    .query_row(
                        "SELECT EXISTS(
                            SELECT 1 FROM sqlite_master
                            WHERE type = 'trigger' AND name = ?1 AND tbl_name = ?2
                         )",
                        (&trigger, table),
                        |row| row.get(0),
                    )
                    .unwrap();
                assert!(exists, "missing rollback fence trigger {trigger}");
            }
        }

        connection
            .execute(
                "INSERT INTO provider_prepared_requests
                 (call_id, prepared_digest, render_digest, profile_digest,
                  record_digest, call_digest_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, 2)",
                params![
                    [1_u8; 16].as_slice(),
                    [2_u8; 32].as_slice(),
                    [3_u8; 32].as_slice(),
                    [4_u8; 32].as_slice(),
                    [5_u8; 32].as_slice(),
                ],
            )
            .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_upgrade_write_latch",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        drop(connection);

        assert_eq!(
            rollback_pre_v12_snapshot(&path),
            Err(SchemaRollbackError::RollbackClosed)
        );
        let unchanged =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(
            unchanged
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            12
        );
        assert_eq!(
            unchanged
                .query_row(
                    "SELECT COUNT(*) FROM provider_prepared_requests",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn tampered_v11_snapshot_is_rejected_without_mutating_v12() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("authoritative.sqlite");
        let connection = Connection::open(&path).unwrap();
        initialize_released_v11(&connection);
        apply_migrations_through(&connection, 12, None).unwrap();
        let snapshot_filename: String = connection
            .query_row(
                "SELECT snapshot_filename FROM schema_upgrade_fence WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(connection);
        let snapshot_path = temporary.path().join(snapshot_filename);
        let mut bytes = fs::read(&snapshot_path).unwrap();
        bytes[128] ^= 0x01;
        fs::write(&snapshot_path, bytes).unwrap();
        secure_file_permissions(&snapshot_path).unwrap();

        assert_eq!(
            rollback_pre_v12_snapshot(&path),
            Err(SchemaRollbackError::SnapshotMismatch)
        );
        let unchanged =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(
            unchanged
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            12
        );
    }

    #[test]
    fn exclusive_upgrade_window_rejects_a_v11_write_after_snapshot_capture() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("authoritative.sqlite");
        let connection = Connection::open(&path).unwrap();
        initialize_released_v11(&connection);
        drop(connection);
        let (captured_tx, captured_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let upgrade_path = path.clone();
        let upgrade = std::thread::spawn(move || {
            let connection = Connection::open(upgrade_path).unwrap();
            let hook = |point| {
                if point == SchemaMaintenancePoint::V11SnapshotCaptured {
                    captured_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                }
            };
            apply_migrations_through(&connection, 12, Some(&hook))
        });
        captured_rx.recv().unwrap();

        let writer = Connection::open(&path).unwrap();
        writer
            .busy_timeout(std::time::Duration::from_millis(50))
            .unwrap();
        assert!(
            writer
                .execute(
                    "INSERT INTO _daemon_info (key, value)
                     VALUES ('raced-v11-write', 'must-not-commit')",
                    [],
                )
                .is_err()
        );
        release_tx.send(()).unwrap();
        upgrade.join().unwrap().unwrap();

        let upgraded =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(
            upgraded
                .query_row(
                    "SELECT COUNT(*) FROM _daemon_info
                     WHERE key = 'raced-v11-write'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn first_v12_write_after_fence_check_closes_rollback_without_data_loss() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("authoritative.sqlite");
        let connection = Connection::open(&path).unwrap();
        initialize_released_v11(&connection);
        apply_migrations_through(&connection, 12, None).unwrap();
        drop(connection);
        let (checked_tx, checked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let rollback_path = path.clone();
        let rollback = std::thread::spawn(move || {
            let hook = |point| {
                if point == SchemaMaintenancePoint::RollbackPreliminaryFenceChecked {
                    checked_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                }
            };
            rollback_pre_v12_snapshot_with_hook(&rollback_path, Some(&hook))
        });
        checked_rx.recv().unwrap();
        let writer = Connection::open(&path).unwrap();
        writer
            .execute(
                "INSERT INTO _daemon_info (key, value)
                 VALUES ('winning-v12-write', 'preserved')",
                [],
            )
            .unwrap();
        drop(writer);
        release_tx.send(()).unwrap();

        assert_eq!(
            rollback.join().unwrap(),
            Err(SchemaRollbackError::RollbackClosed)
        );
        let unchanged =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(
            unchanged
                .query_row(
                    "SELECT value FROM _daemon_info
                     WHERE key = 'winning-v12-write'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "preserved"
        );
        assert_eq!(
            unchanged
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            12
        );
    }

    #[test]
    fn write_before_unavailable_cutover_closes_rollback_and_preserves_v12() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("authoritative.sqlite");
        let connection = Connection::open(&path).unwrap();
        initialize_released_v11(&connection);
        apply_migrations_through(&connection, 12, None).unwrap();
        drop(connection);
        let (verified_tx, verified_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let rollback_path = path.clone();
        let rollback = std::thread::spawn(move || {
            let hook = |point| {
                if point == SchemaMaintenancePoint::RollbackBeforeCutover {
                    verified_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                }
            };
            rollback_pre_v12_snapshot_with_hook(&rollback_path, Some(&hook))
        });
        verified_rx.recv().unwrap();

        let writer = Connection::open(&path).unwrap();
        writer
            .execute(
                "INSERT INTO _daemon_info (key, value)
                 VALUES ('winning-v12-write-before-cutover', 'preserved')",
                [],
            )
            .unwrap();
        release_tx.send(()).unwrap();
        assert_eq!(
            rollback.join().unwrap(),
            Err(SchemaRollbackError::RollbackClosed)
        );
        let unchanged =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(
            unchanged
                .query_row(
                    "SELECT value FROM _daemon_info
                     WHERE key = 'winning-v12-write-before-cutover'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "preserved"
        );
        assert_eq!(
            unchanged
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            12
        );
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_path_substitution_after_digest_check_never_changes_main_database() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("authoritative.sqlite");
        let connection = Connection::open(&path).unwrap();
        initialize_released_v11(&connection);
        apply_migrations_through(&connection, 12, None).unwrap();
        let snapshot_filename: String = connection
            .query_row(
                "SELECT snapshot_filename FROM schema_upgrade_fence WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(connection);
        let snapshot_path = temporary.path().join(snapshot_filename);
        let held_path = temporary.path().join("held-original-v11.sqlite");
        let hook = |point| {
            if point == SchemaMaintenancePoint::RollbackSnapshotVerified {
                fs::rename(&snapshot_path, &held_path).unwrap();
                let mut replacement = fs::read(&held_path).unwrap();
                replacement[256] ^= 0x01;
                fs::write(&snapshot_path, replacement).unwrap();
                secure_file_permissions(&snapshot_path).unwrap();
            }
        };

        assert_eq!(
            rollback_pre_v12_snapshot_with_hook(&path, Some(&hook)),
            Err(SchemaRollbackError::SnapshotMismatch)
        );
        let unchanged =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(
            unchanged
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            12
        );
    }

    #[test]
    fn v12_write_latch_is_irreversible_and_extra_trigger_is_not_released_schema() {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_through(&connection, 12, None).unwrap();
        connection
            .execute(
                "INSERT INTO _daemon_info (key, value) VALUES ('close-latch', '1')",
                [],
            )
            .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_upgrade_write_latch",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert!(
            connection
                .execute("DELETE FROM schema_upgrade_write_latch", [])
                .is_err()
        );
        connection
            .execute_batch(
                "CREATE TRIGGER extra_provider_trigger
                 AFTER UPDATE ON provider_prepared_requests
                 BEGIN SELECT 1; END;",
            )
            .unwrap();
        assert!(!is_released_provider_v12(&connection, 12).unwrap());
    }

    #[test]
    fn released_v13_requires_the_exact_catalog_and_table_shapes() {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations(&connection).unwrap();
        assert!(is_released_provider_v13(&connection, 13).unwrap());

        connection
            .execute_batch(
                "CREATE TRIGGER extra_v13_provider_trigger
                 AFTER UPDATE ON provider_terminal_outbox
                 BEGIN SELECT 1; END;",
            )
            .unwrap();
        assert!(!is_released_provider_v13(&connection, 13).unwrap());

        connection
            .execute_batch(
                "DROP TRIGGER extra_v13_provider_trigger;
                 ALTER TABLE provider_terminal_outbox ADD COLUMN unexpected TEXT;",
            )
            .unwrap();
        assert!(!is_released_provider_v13(&connection, 13).unwrap());
    }

    #[test]
    fn released_v8_upgrades_atomically_through_provider_v12() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_released_v8(&conn);

        apply_migrations_through(&conn, 12, None).unwrap();

        assert_eq!(CURRENT_SCHEMA_VERSION, 13);
        assert_eq!(
            conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            12
        );
        assert!(
            conn.execute(
                "INSERT INTO consumption_intents VALUES (?1, 'key', 'Reserved', ?2, ?2, ?2)",
                params![[1_u8; 15].as_slice(), [2_u8; 32].as_slice()]
            )
            .is_err()
        );
        assert!(conn.execute("INSERT INTO verification_evidence VALUES (?1, ?1, ?1, ?2, 6, 0, ?2, 'blob:test', 'store', 'producer', 0, 'sqlite')", params![[1_u8; 16].as_slice(), [2_u8; 32].as_slice()]).is_err());
    }

    #[test]
    fn released_v11_provider_rows_upgrade_as_v1_without_digest_rewrite() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_released_v8(&conn);
        for (version, migration) in [(9, MIGRATION_V9), (10, MIGRATION_V10), (11, MIGRATION_V11)] {
            let tx = conn.unchecked_transaction().unwrap();
            tx.execute_batch(migration).unwrap();
            tx.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [version],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        for state in 1_i64..=4 {
            let call_id = [u8::try_from(state).unwrap(); 16];
            conn.execute(
                "INSERT INTO provider_prepared_requests
                 (call_id, prepared_digest, render_digest, profile_digest, record_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    call_id.as_slice(),
                    [2_u8; 32].as_slice(),
                    [3_u8; 32].as_slice(),
                    [4_u8; 32].as_slice(),
                    [5_u8; 32].as_slice(),
                ],
            )
            .unwrap();
            let attempt_id = [u8::try_from(state + 10).unwrap(); 16];
            let permit_id = [u8::try_from(state + 20).unwrap(); 16];
            let stream_id = (state == 2).then_some([9_u8; 16]);
            let settlement_digest = (state == 3).then_some([10_u8; 32]);
            conn.execute(
                "INSERT INTO provider_dispatch_attempts
                 (attempt_id, call_id, permit_id, token_reservation_id,
                  cost_reservation_id, fencing_token, provider_idempotency_key,
                  prepared_digest, render_digest, profile_digest, state,
                  stream_id, settlement_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    attempt_id.as_slice(),
                    call_id.as_slice(),
                    permit_id.as_slice(),
                    [6_u8; 16].as_slice(),
                    [7_u8; 16].as_slice(),
                    state,
                    format!("released-v11-state-{state}"),
                    [2_u8; 32].as_slice(),
                    [3_u8; 32].as_slice(),
                    [4_u8; 32].as_slice(),
                    state,
                    stream_id.as_ref().map(<[u8; 16]>::as_slice),
                    settlement_digest.as_ref().map(<[u8; 32]>::as_slice),
                ],
            )
            .unwrap();
        }

        apply_migrations_through(&conn, 12, None).unwrap();

        let (version, prepared_digest): (i64, Vec<u8>) = conn
            .query_row(
                "SELECT call_digest_version, prepared_digest
                 FROM provider_prepared_requests WHERE call_id = ?1",
                [[1_u8; 16].as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(version, 1);
        assert_eq!(prepared_digest, vec![2_u8; 32]);
        for (old_state, expected_v12_state) in [(1_i64, 1_i64), (2, 3), (3, 5), (4, 6)] {
            let call_id = [u8::try_from(old_state).unwrap(); 16];
            let (state, rejection, stream_id): (i64, Option<i64>, Option<Vec<u8>>) = conn
                .query_row(
                    "SELECT state, pre_effect_rejection, stream_id
                     FROM provider_dispatch_attempts WHERE call_id = ?1",
                    [call_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(state, expected_v12_state);
            assert_eq!(rejection, None);
            assert_eq!(stream_id.is_some(), old_state == 2);
        }
        assert_eq!(
            conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            12
        );
    }

    #[test]
    fn candidate_or_future_markers_are_rejected_without_mutation() {
        for marker in [9, 10, 11, 12, 13, 14] {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now'))); CREATE TABLE candidate_data (value TEXT NOT NULL);").unwrap();
            conn.execute("INSERT INTO schema_version (version) VALUES (?1)", [marker])
                .unwrap();
            conn.execute("INSERT INTO candidate_data VALUES ('unchanged')", [])
                .unwrap();
            let before: Vec<(String, String)> = conn
                .prepare("SELECT type, name FROM sqlite_master ORDER BY type, name")
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<SqliteResult<_>>()
                .unwrap();

            assert!(
                apply_migrations(&conn).is_err(),
                "candidate marker V{marker} must fail closed"
            );

            let after: Vec<(String, String)> = conn
                .prepare("SELECT type, name FROM sqlite_master ORDER BY type, name")
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<SqliteResult<_>>()
                .unwrap();
            assert_eq!(after, before);
            assert_eq!(
                conn.query_row("SELECT value FROM candidate_data", [], |row| row
                    .get::<_, String>(0))
                    .unwrap(),
                "unchanged"
            );
        }
    }

    #[test]
    fn tampered_candidate_intent_digest_is_rejected_not_recomputed() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')));
             CREATE TABLE consumption_intents (intent_id BLOB PRIMARY KEY, idempotency_key TEXT NOT NULL, state TEXT NOT NULL, gate_head_snapshot_digest BLOB NOT NULL, target_artifact_digest BLOB NOT NULL, integrity_digest BLOB NOT NULL);",
        )
        .unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (9)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO consumption_intents VALUES (?1, 'legacy', 'Reserved', ?2, ?2, ?3)",
            params![
                [1_u8; 16].as_slice(),
                [2_u8; 32].as_slice(),
                [0xA5_u8; 32].as_slice()
            ],
        )
        .unwrap();

        assert!(apply_migrations(&conn).is_err());

        let digest: Vec<u8> = conn
            .query_row(
                "SELECT integrity_digest FROM consumption_intents",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(digest, vec![0xA5; 32]);
    }

    // Released V8 has no verification tables, so no released legacy intent
    // digest exists to validate or rewrite. Candidate V9+ inputs reject above.

    fn artifact_blob_prefix(table: &str) -> &'static str {
        match table {
            "migration_reports" => "report",
            "cutover_manifests" | "rollback_manifests" | "retirement_manifests" => "manifest",
            _ => unreachable!("test controls the table list"),
        }
    }
}
