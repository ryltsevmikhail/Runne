//! Bootstrap subsystem — full daemon startup sequence.
//!
//! Implements ADR-0014 bootstrap sequence:
//! acquire three-layer locks, provision or load the replay-integrity key,
//! open the SQLite database, apply schema migrations, reconcile
//! authority metadata, purge stale replay subscriptions, and
//! detect recovery tasks.
//!
//! ## Lock acquisition order
//!
//! 1. Provisional path lock — before DB open, serialises first-start
//!    and replay-key side effects.
//! 2. File identity lock — after DB verify handle (no-follow open).
//! 3. Authority lock — after reading/generating `_authority` from schema v8 DB.

use crate::config::ConfigurationSnapshot;
use crate::error::DaemonError;
use crate::launch_identity::LaunchIdentity;
use crate::lock::{LockSet, MetadataSnapshot};
use crate::replay_key::{ReplayIntegrityKey, ReplayIntegrityKeyManager};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use gocode_api::PendingFirstActivationV1;
use gocode_domain::id::validate_uuid_v7_bytes;
use gocode_store::schema;
use gocode_store::schema::LaunchAuthorityConsumptionError;
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

const SIDECAR_MIGRATION_MARKER_KEY: &str = "local_session_sidecars_v1";

// ── Startup mode ──────────────────────────────────────────────────────

/// Describes how the daemon started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupMode {
    /// First time this Event Log has been initialised.
    FirstStart,
    /// Normal restart — DB and metadata existed.
    Restart,
    /// Restart after a recovery phase (currently informational).
    Recovered,
}

// ── BootstrapOutcome ──────────────────────────────────────────────────

/// The complete set of resources acquired during bootstrap.
///
/// All three locks are held, the database is open and migrated,
/// the replay-integrity key is loaded or provisioned.
pub struct BootstrapOutcome {
    /// All three locks held (path, file, authority).
    pub locks: LockSet,
    /// Open writable SQLite connection with schema applied.
    pub db_conn: rusqlite::Connection,
    /// Authority ID from the `_authority` table.
    pub authority_id: [u8; 16],
    /// Stable UUIDv7 authority for peer-authenticated local sessions.
    pub local_session_authority_id: [u8; 16],
    /// Whether the DB file existed before this bootstrap.
    pub db_existed: bool,
    /// How the daemon started.
    pub startup_mode: StartupMode,
    /// Fresh TLS and bootstrap identity for this daemon launch.
    pub launch_identity: LaunchIdentity,
    /// Durable positive generation allocated for this launch.
    pub launch_generation: u64,
    /// Stable internal replay-integrity key.
    pub replay_integrity_key: ReplayIntegrityKey,
}

impl std::fmt::Debug for BootstrapOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapOutcome")
            .field("locks", &self.locks)
            .field("db_conn", &"<Connection>")
            .field("authority_id", &hex::encode(self.authority_id))
            .field("local_session_authority_id", &"<redacted>")
            .field("db_existed", &self.db_existed)
            .field("startup_mode", &self.startup_mode)
            .field("launch_identity", &"<redacted>")
            .field("launch_generation", &self.launch_generation)
            .field("replay_integrity_key", &"<redacted>")
            .finish()
    }
}

// ── Public API ────────────────────────────────────────────────────────

/// Full bootstrap sequence.
///
/// Returns a `BootstrapOutcome` with all acquired resources, or a
/// `DaemonError` for fatal startup failures (invalid replay key, DB change
/// under live lock, authority without Event Log, etc.).
pub fn bootstrap(config: &ConfigurationSnapshot) -> Result<BootstrapOutcome, DaemonError> {
    bootstrap_inner(config, None)
}

struct ProtectedBootstrap<'a> {
    launch_authority_id: [u8; 16],
    bootstrap_secret: [u8; 32],
    pending_first_activation: Option<&'a PendingFirstActivationV1>,
    freshness_check: &'a mut dyn FnMut() -> Result<(), DaemonError>,
}

/// Bootstraps one protected bundled launch without publishing a credential profile.
pub fn bootstrap_protected<F>(
    config: &ConfigurationSnapshot,
    launch_authority_id: [u8; 16],
    bootstrap_secret: [u8; 32],
    pending_first_activation: Option<&PendingFirstActivationV1>,
    mut freshness_check: F,
) -> Result<BootstrapOutcome, DaemonError>
where
    F: FnMut() -> Result<(), DaemonError>,
{
    if validate_uuid_v7_bytes(&launch_authority_id).is_err() || bootstrap_secret == [0; 32] {
        return Err(DaemonError::Bootstrap(
            "invalid protected launch authority".into(),
        ));
    }
    bootstrap_inner(
        config,
        Some(ProtectedBootstrap {
            launch_authority_id,
            bootstrap_secret,
            pending_first_activation,
            freshness_check: &mut freshness_check,
        }),
    )
}

fn bootstrap_inner(
    config: &ConfigurationSnapshot,
    mut protected: Option<ProtectedBootstrap<'_>>,
) -> Result<BootstrapOutcome, DaemonError> {
    let db_path = PathBuf::from(&config.db_path);
    let replay_integrity_key_path = PathBuf::from(&config.replay_integrity_key_path);

    // Derive runtime dir from config paths (parent of gocode-daemon/).
    let daemon_dir = db_path
        .parent()
        .ok_or_else(|| DaemonError::Bootstrap("db_path has no parent directory".into()))?
        .to_path_buf();
    let runtime_dir = daemon_dir
        .parent()
        .ok_or_else(|| DaemonError::Bootstrap("daemon dir has no parent".into()))?
        .to_path_buf();

    // ── Step 2 & 3: canonicalise parent, create runtime dir ────────
    ensure_dir_secured(&daemon_dir)?;

    // ── Step 6: check DB existence BEFORE any file creation ─────────
    let db_existed = db_path.exists();
    if protected.is_some()
        && !db_existed
        && protected
            .as_ref()
            .and_then(|value| value.pending_first_activation)
            .is_none()
    {
        return Err(DaemonError::Bootstrap(
            "protected first activation was not prepared".into(),
        ));
    }

    // ── Step 4: acquire provisional path lock ───────────────────────
    let mut locks = LockSet::acquire_path(&db_path, &runtime_dir)
        .map_err(|e| DaemonError::Bootstrap(format!("path lock: {e}")))?;

    // ── Step 5: read pre-open metadata snapshot ─────────────────────
    let metadata_snapshot = locks
        .read_metadata_snapshot()
        .map_err(|e| DaemonError::Bootstrap(format!("read metadata: {e}")))?;

    // ── Step 7: determine startup mode ──────────────────────────────
    let startup_mode = match (&metadata_snapshot, db_existed) {
        (MetadataSnapshot::Empty, false) => StartupMode::FirstStart,
        _ => StartupMode::Restart,
    };

    // ── Step 9: DB verify / create ──────────────────────────────────
    if db_existed {
        // Open verify handle (no-follow) for existing DB
        let db_handle = open_verify_no_follow(&db_path)?;
        locks
            .acquire_file_lock(&db_handle, &runtime_dir)
            .map_err(|e| DaemonError::Bootstrap(format!("file lock: {e}")))?;
    }
    // ── Step 10: open SQLite writable ───────────────────────────────
    let db_conn = schema::open_with_pragmas(&config.db_path)
        .map_err(|e| DaemonError::Bootstrap(format!("open DB: {e}")))?;

    // ── Step 11: schema migration ───────────────────────────────────
    schema::apply_migrations(&db_conn)
        .map_err(|e| DaemonError::Bootstrap(format!("schema migration: {e}")))?;
    // ── Step 12: authority ID ───────────────────────────────────────
    let prepared_authority = protected
        .as_ref()
        .and_then(|value| value.pending_first_activation)
        .map(|pending| *pending.stable().authority_id());
    let (authority_id, db_authority_after) = acquire_authority(
        db_existed,
        &db_conn,
        &mut locks,
        &runtime_dir,
        prepared_authority,
    )?;
    if let Some(pending) = protected
        .as_ref()
        .and_then(|value| value.pending_first_activation)
    {
        let expected_lineage = uuid::Uuid::from_bytes(*pending.stable().lineage_id())
            .to_string()
            .parse()
            .map_err(|_| DaemonError::Bootstrap("invalid prepared Event Log lineage".into()))?;
        if authority_id != *pending.stable().authority_id() {
            return Err(DaemonError::Bootstrap(
                "prepared stable authority mismatch".into(),
            ));
        }
        schema::ensure_exact_first_activation_identity(
            &db_conn,
            pending.stable().authority_id(),
            expected_lineage,
            pending.preparation_id(),
        )
        .map_err(|_| DaemonError::Bootstrap("prepared first activation mismatch".into()))?;
    }
    let (replay_integrity_key, local_session_authority_id) =
        load_or_migrate_local_sidecars(&db_conn, &replay_integrity_key_path, authority_id)?;
    if let Some(protected) = protected.as_mut() {
        if let Some(pending) = protected.pending_first_activation
            && local_session_authority_id != *pending.stable().authority_id()
        {
            return Err(DaemonError::Bootstrap(
                "prepared stable authority mismatch".into(),
            ));
        }
        (protected.freshness_check)()?;
        schema::consume_protected_launch_authority(&db_conn, &protected.launch_authority_id)
            .map_err(|error| match error {
                LaunchAuthorityConsumptionError::AlreadyConsumed => {
                    DaemonError::Bootstrap("protected launch authority already consumed".into())
                }
                LaunchAuthorityConsumptionError::InvalidAuthority
                | LaunchAuthorityConsumptionError::Storage => {
                    DaemonError::Bootstrap("consume protected launch authority".into())
                }
            })?;
    }
    let launch_generation = schema::next_launch_generation(&db_conn)
        .map_err(|_| DaemonError::Bootstrap("allocate launch generation: corrupt state".into()))?;
    let launch_identity = if let Some(protected) = protected.as_ref() {
        LaunchIdentity::generate_protected(launch_generation, protected.bootstrap_secret)
    } else {
        LaunchIdentity::generate(launch_generation)
    }
    .map_err(|_| DaemonError::Bootstrap("generate launch TLS identity".into()))?;

    // ── Step 13: reconcile metadata ─────────────────────────────────
    reconcile_metadata(
        &metadata_snapshot,
        db_existed,
        &db_authority_after,
        &authority_id,
        &locks,
    )?;

    // Verify metadata was written correctly
    verify_metadata_writeback(&locks, &authority_id)?;

    // ── Step 14: startup purge ──────────────────────────────────────
    schema::purge_replay_subscriptions(&db_conn)
        .map_err(|e| DaemonError::Bootstrap(format!("startup purge: {e}")))?;

    // ── Step 15: recovery is informational; caller may invoke
    //    `crate::recovery::enumerate_recovery_tasks` separately. ──────

    Ok(BootstrapOutcome {
        locks,
        db_conn,
        authority_id,
        local_session_authority_id,
        db_existed,
        startup_mode,
        launch_identity,
        launch_generation,
        replay_integrity_key,
    })
}

struct SidecarMigrationMarker {
    replay_key_digest: [u8; 32],
    local_authority_digest: [u8; 32],
}

fn load_or_migrate_local_sidecars(
    conn: &rusqlite::Connection,
    replay_key_path: &Path,
    database_authority: [u8; 16],
) -> Result<(ReplayIntegrityKey, [u8; 16]), DaemonError> {
    let authority_path = replay_key_path.with_file_name("local-session-authority-id");
    match read_sidecar_migration_marker(conn)? {
        Some(marker) => {
            let replay_key = ReplayIntegrityKeyManager::load_existing(replay_key_path)
                .map_err(|_| sidecar_state_error())?;
            let local_authority =
                load_local_session_authority(&authority_path).map_err(|_| sidecar_state_error())?;
            if replay_key.sidecar_digest() != marker.replay_key_digest
                || Sha256::digest(local_authority).as_slice() != marker.local_authority_digest
            {
                return Err(sidecar_state_error());
            }
            Ok((replay_key, local_authority))
        }
        None => {
            let replay_key = ReplayIntegrityKeyManager::load_or_provision(replay_key_path)
                .map_err(|_| sidecar_state_error())?;
            let local_authority =
                load_or_provision_local_session_authority(&authority_path, database_authority)?;
            let marker = SidecarMigrationMarker {
                replay_key_digest: replay_key.sidecar_digest(),
                local_authority_digest: Sha256::digest(local_authority).into(),
            };
            write_sidecar_migration_marker(conn, &marker)?;
            Ok((replay_key, local_authority))
        }
    }
}

/// Read-only validation for sidecars left before first launch consumption.
pub(crate) fn preflight_recoverable_first_activation_sidecars(
    config: &ConfigurationSnapshot,
    expected_authority: &[u8; 16],
) -> Result<(), DaemonError> {
    let replay_key_path = Path::new(&config.replay_integrity_key_path);
    let authority_path = replay_key_path.with_file_name("local-session-authority-id");
    let db = rusqlite::Connection::open_with_flags(
        &config.db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| sidecar_state_error())?;
    match read_sidecar_migration_marker(&db)? {
        Some(marker) => {
            let replay_key = ReplayIntegrityKeyManager::load_existing(replay_key_path)
                .map_err(|_| sidecar_state_error())?;
            let authority =
                load_local_session_authority(&authority_path).map_err(|_| sidecar_state_error())?;
            if &authority != expected_authority
                || replay_key.sidecar_digest() != marker.replay_key_digest
                || Sha256::digest(authority).as_slice() != marker.local_authority_digest
            {
                return Err(sidecar_state_error());
            }
        }
        None => {
            if replay_key_path.exists() {
                ReplayIntegrityKeyManager::load_existing(replay_key_path)
                    .map_err(|_| sidecar_state_error())?;
            }
            if authority_path.exists() {
                match load_local_session_authority(&authority_path) {
                    Ok(authority) if authority == *expected_authority => {}
                    Ok(_) | Err(_) => return Err(sidecar_state_error()),
                }
            }
        }
    }
    Ok(())
}

fn read_sidecar_migration_marker(
    conn: &rusqlite::Connection,
) -> Result<Option<SidecarMigrationMarker>, DaemonError> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = ?1",
            [SIDECAR_MIGRATION_MARKER_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| sidecar_state_error())?;
    value
        .map(|value| parse_sidecar_migration_marker(&value))
        .transpose()
}

fn parse_sidecar_migration_marker(value: &str) -> Result<SidecarMigrationMarker, DaemonError> {
    let mut parts = value.split(':');
    let (Some("1"), Some(replay_digest), Some(authority_digest), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(sidecar_state_error());
    };
    Ok(SidecarMigrationMarker {
        replay_key_digest: decode_lower_hex_32(replay_digest)?,
        local_authority_digest: decode_lower_hex_32(authority_digest)?,
    })
}

fn write_sidecar_migration_marker(
    conn: &rusqlite::Connection,
    marker: &SidecarMigrationMarker,
) -> Result<(), DaemonError> {
    let value = format!(
        "1:{}:{}",
        hex::encode(marker.replay_key_digest),
        hex::encode(marker.local_authority_digest)
    );
    conn.execute(
        "INSERT INTO _daemon_info (key, value) VALUES (?1, ?2)",
        (SIDECAR_MIGRATION_MARKER_KEY, value),
    )
    .map_err(|_| sidecar_state_error())?;
    Ok(())
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], DaemonError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(sidecar_state_error());
    }
    let mut output = [0; 32];
    hex::decode_to_slice(value, &mut output).map_err(|_| sidecar_state_error())?;
    Ok(output)
}

fn sidecar_state_error() -> DaemonError {
    DaemonError::Bootstrap("load local session sidecar state".into())
}

fn load_or_provision_local_session_authority(
    path: &Path,
    database_authority: [u8; 16],
) -> Result<[u8; 16], DaemonError> {
    match load_local_session_authority(path) {
        Ok(authority) => return Ok(authority),
        Err(_) if path.exists() => {
            return Err(DaemonError::Bootstrap(
                "load local session authority".into(),
            ));
        }
        Err(_) => {}
    }
    let authority = if validate_uuid_v7_bytes(&database_authority).is_ok() {
        database_authority
    } else {
        *uuid::Uuid::now_v7().as_bytes()
    };
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(crate::lock::O_NOFOLLOW_VAL);
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(_) if path.exists() => return load_local_session_authority(path),
        Err(_) => {
            return Err(DaemonError::Bootstrap(
                "provision local session authority".into(),
            ));
        }
    };
    file.write_all(&authority)
        .and_then(|()| file.sync_all())
        .map_err(|_| DaemonError::Bootstrap("provision local session authority".into()))?;
    Ok(authority)
}

fn load_local_session_authority(path: &Path) -> Result<[u8; 16], DaemonError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(crate::lock::O_NOFOLLOW_VAL);
    }
    let mut file = options
        .open(path)
        .map_err(|_| DaemonError::Bootstrap("load local session authority".into()))?;
    let metadata = file
        .metadata()
        .map_err(|_| DaemonError::Bootstrap("load local session authority".into()))?;
    if !metadata.file_type().is_file() {
        return Err(DaemonError::Bootstrap(
            "load local session authority".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(DaemonError::Bootstrap(
                "load local session authority".into(),
            ));
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| DaemonError::Bootstrap("load local session authority".into()))?;
    let authority: [u8; 16] = bytes
        .try_into()
        .map_err(|_| DaemonError::Bootstrap("load local session authority".into()))?;
    validate_uuid_v7_bytes(&authority)
        .map_err(|_| DaemonError::Bootstrap("load local session authority".into()))?;
    Ok(authority)
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Ensure `dir` exists with secure permissions (0700).
fn ensure_dir_secured(dir: &Path) -> Result<(), DaemonError> {
    fs::create_dir_all(dir)
        .map_err(|e| DaemonError::Bootstrap(format!("cannot create {dir:?}: {e}")))?;
    schema::secure_dir_permissions(dir)
        .map_err(|e| DaemonError::Bootstrap(format!("cannot secure {dir:?}: {e}")))
}

/// Open DB file with no-follow for verify / file-identity lock.
fn open_verify_no_follow(db_path: &Path) -> Result<fs::File, DaemonError> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true).write(false).create(false);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        const O_NOFOLLOW: i32 = 0x0100;
        const O_CLOEXEC: i32 = 0x1000000;
        opts.custom_flags(O_NOFOLLOW | O_CLOEXEC);
    }

    opts.open(db_path)
        .map_err(|e| DaemonError::Bootstrap(format!("cannot open DB for verify: {e}")))
}

/// Read, generate, or validate the authority ID.
///
/// Returns `(authority_id, db_authority_after)` where `db_authority_after`
/// is `Some` with the authority that is now in the database.
fn acquire_authority(
    db_existed: bool,
    conn: &rusqlite::Connection,
    locks: &mut LockSet,
    runtime_dir: &Path,
    prepared_authority: Option<[u8; 16]>,
) -> Result<([u8; 16], Option<[u8; 16]>), DaemonError> {
    let db_authority = schema::read_authority_id(conn)
        .map_err(|e| DaemonError::Bootstrap(format!("read authority: {e}")))?;

    match (db_existed, db_authority) {
        // New DB — generate fresh authority
        (false, None) => {
            let aid = prepared_authority.unwrap_or_else(|| *uuid::Uuid::now_v7().as_bytes());
            schema::ensure_authority_id(conn, &aid)
                .map_err(|e| DaemonError::Bootstrap(format!("ensure authority: {e}")))?;

            locks
                .acquire_authority_lock(&aid, runtime_dir)
                .map_err(|e| DaemonError::Bootstrap(format!("authority lock: {e}")))?;

            // Re-read to confirm
            let after = schema::read_authority_id(conn)
                .map_err(|e| DaemonError::Bootstrap(format!("re-read authority: {e}")))?;
            Ok((aid, after))
        }

        // New DB somehow already has authority (shouldn't happen outside backup restore)
        (false, Some(_)) => Err(DaemonError::Bootstrap(
            "newly created DB unexpectedly has authority ID".into(),
        )),

        // Existing DB — must have authority
        (true, Some(aid)) => {
            if prepared_authority.is_some_and(|prepared| prepared != aid) {
                return Err(DaemonError::Bootstrap(
                    "prepared authority does not match Event Log".into(),
                ));
            }
            locks
                .acquire_authority_lock(&aid, runtime_dir)
                .map_err(|e| DaemonError::Bootstrap(format!("authority lock: {e}")))?;
            Ok((aid, Some(aid)))
        }

        // Existing DB without authority — schema corruption
        (true, None) => Err(DaemonError::Bootstrap(
            "existing DB has no authority ID".into(),
        )),
    }
}

/// Reconcile lock metadata with DB authority.
///
/// This implements the crash-recovery table from ADR-0014 §6:
///
/// | Metadata | DB exists | DB authority | Action |
/// |----------|-----------|-------------|--------|
/// | Valid (=) | yes      | =           | nothing |
/// | Valid (!=)| yes      | !=          | **exit 5** |
/// | Empty    | yes      | present     | write metadata (upgrade) |
/// | Malformed| yes      | present     | write metadata (repair) |
/// | Empty    | no       | generated   | write metadata (first start) |
/// | Valid/Malformed | no | *         | **exit 5** |
fn reconcile_metadata(
    snapshot: &MetadataSnapshot,
    db_existed: bool,
    db_authority: &Option<[u8; 16]>,
    authority_id: &[u8; 16],
    locks: &LockSet,
) -> Result<(), DaemonError> {
    match (snapshot, db_existed, db_authority) {
        // Normal restart — authority matches lock metadata
        (
            MetadataSnapshot::Valid {
                authority_id: expected,
            },
            true,
            Some(present),
        ) if *expected == *present => {
            // Nothing to do
        }

        // Authority mismatch — DB was replaced under a live lock (exit 5)
        (MetadataSnapshot::Valid { .. }, true, Some(_)) => {
            return Err(DaemonError::Bootstrap(
                "authority mismatch: DB replaced".into(),
            ));
        }

        // Upgrade: empty metadata on existing DB — publish authority
        (MetadataSnapshot::Empty, true, Some(present)) => {
            locks
                .write_metadata(present)
                .map_err(|e| DaemonError::Bootstrap(format!("write metadata (upgrade): {e}")))?;
        }

        // Repair torn metadata on existing DB
        (MetadataSnapshot::Malformed, true, Some(present)) => {
            locks
                .write_metadata(present)
                .map_err(|e| DaemonError::Bootstrap(format!("write metadata (repair): {e}")))?;
        }

        // First start: empty metadata, no DB existed, authority just generated
        (MetadataSnapshot::Empty, false, _) => {
            locks.write_metadata(authority_id).map_err(|e| {
                DaemonError::Bootstrap(format!("write metadata (first start): {e}"))
            })?;
        }

        // Authority published but DB does not exist (exit 5)
        (MetadataSnapshot::Valid { .. } | MetadataSnapshot::Malformed, false, _) => {
            return Err(DaemonError::Bootstrap("authority without Event Log".into()));
        }

        // Catch-all for unexpected combinations
        _ => {
            return Err(DaemonError::Bootstrap(format!(
                "unexpected bootstrap state: \
                 metadata={:?}, db_existed={}, authority={:?}",
                snapshot, db_existed, db_authority
            )));
        }
    }

    Ok(())
}

/// Verify metadata writeback: re-read and check version, length, CRC, authority_id.
fn verify_metadata_writeback(locks: &LockSet, authority_id: &[u8; 16]) -> Result<(), DaemonError> {
    let snap = locks
        .read_metadata_snapshot()
        .map_err(|e| DaemonError::Bootstrap(format!("verify metadata readback: {e}")))?;

    match &snap {
        MetadataSnapshot::Valid {
            authority_id: verified,
        } if *verified == *authority_id => Ok(()),

        MetadataSnapshot::Valid { .. } => Err(DaemonError::Bootstrap(
            "metadata write verification failed: authority mismatch".into(),
        )),

        _ => Err(DaemonError::Bootstrap(
            "metadata write verification failed: record is not valid".into(),
        )),
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BuiltInDefaults;
    use tempfile::TempDir;

    /// Build a `ConfigurationSnapshot` rooted at a temp dir.
    fn test_config(temp: &TempDir) -> ConfigurationSnapshot {
        let defaults = BuiltInDefaults::new(temp.path());
        ConfigurationSnapshot::from_defaults(&defaults)
    }

    // ── 1. first_start_creates_db_and_replay_key ────────────────
    #[test]
    fn first_start_creates_db_and_replay_key() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        let outcome = bootstrap(&config).unwrap();

        assert!(!outcome.db_existed);
        assert_eq!(outcome.startup_mode, StartupMode::FirstStart);
        assert!(PathBuf::from(&config.db_path).exists());
        assert!(PathBuf::from(&config.replay_integrity_key_path).exists());
        // file_lock is only acquired for existing DBs (no hardlink
        // risk on a fresh create); authority_lock must be held.
        assert!(outcome.locks.authority_lock.is_some());
    }

    // ── 2. restart_reuses_existing_db ──────────────────────────
    #[test]
    fn restart_reuses_existing_db() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        // First bootstrap
        let o1 = bootstrap(&config).unwrap();
        assert!(!o1.db_existed);
        assert_eq!(o1.startup_mode, StartupMode::FirstStart);
        let aid1 = o1.authority_id;
        drop(o1);

        // Second bootstrap — must find existing DB
        let o2 = bootstrap(&config).unwrap();
        assert!(o2.db_existed);
        assert_eq!(o2.startup_mode, StartupMode::Restart);
        assert_eq!(o2.authority_id, aid1);
    }

    // ── 3. crash_before_metadata_publish_is_repaired ────────────
    #[test]
    fn crash_before_metadata_publish_is_repaired() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        // Step 1: do a full bootstrap to create the DB + authority
        let o1 = bootstrap(&config).unwrap();
        let aid = o1.authority_id;
        drop(o1);

        // Step 2: simulate crash by clearing lock metadata
        // We need to acquire the lock, clear metadata, release.
        let db_path = PathBuf::from(&config.db_path);
        let daemon_dir = db_path.parent().unwrap();
        let runtime_dir = daemon_dir.parent().unwrap();

        {
            let locks = LockSet::acquire_path(&db_path, runtime_dir).unwrap();
            // Truncate the metadata to zero bytes
            let f = locks.path_lock.file();
            f.set_len(0).unwrap();
            f.sync_all().unwrap();
        }

        // Step 3: bootstrap again — must repair metadata, not error
        let o2 = bootstrap(&config).unwrap();
        assert!(o2.db_existed);
        assert_eq!(o2.startup_mode, StartupMode::Restart);
        assert_eq!(o2.authority_id, aid);
    }

    // ── 4. authority_mismatch_causes_exit5 ──────────────────────
    #[test]
    fn authority_mismatch_causes_exit5() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        // Full bootstrap to create state
        let o1 = bootstrap(&config).unwrap();
        drop(o1);

        // Write a different authority into lock metadata
        let db_path = PathBuf::from(&config.db_path);
        let daemon_dir = db_path.parent().unwrap();
        let runtime_dir = daemon_dir.parent().unwrap();
        let wrong_aid: [u8; 16] = [0xDE; 16];

        {
            let locks = LockSet::acquire_path(&db_path, runtime_dir).unwrap();
            locks.write_metadata(&wrong_aid).unwrap();
        }

        // Bootstrap must fail with Bootstrap error
        let result = bootstrap(&config);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("authority mismatch") || msg.contains("bootstrap error"),
            "expected authority mismatch, got: {msg}"
        );
    }

    // ── 5. published_authority_without_db_causes_exit5 ──────────
    #[test]
    fn published_authority_without_db_causes_exit5() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        // Manually create metadata *without* the DB file
        let db_path = PathBuf::from(&config.db_path);
        let daemon_dir = db_path.parent().unwrap();
        let runtime_dir = daemon_dir.parent().unwrap();

        // Create daemon dir (so lock file can be stored)
        fs::create_dir_all(daemon_dir).unwrap();

        let fake_aid: [u8; 16] = [0xFA; 16];
        {
            // We need the DB file to exist for lock acquisition
            fs::File::create(&db_path).unwrap();
            let locks = LockSet::acquire_path(&db_path, runtime_dir).unwrap();
            locks.write_metadata(&fake_aid).unwrap();
            // Close lock, remove DB file, but leave metadata
        }
        fs::remove_file(&db_path).unwrap();

        // Bootstrap must fail because metadata exists but DB is gone
        let result = bootstrap(&config);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("bootstrap error") || msg.contains("authority"),
            "expected authority-without-db error, got: {msg}"
        );
    }

    // ── 6. restart_with_existing_replay_key_loads_correctly ─────
    #[test]
    fn restart_with_existing_replay_key_loads_correctly() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        let o1 = bootstrap(&config).unwrap();
        let marker = o1.replay_integrity_key.derive_hmac(b"persistence-test");
        drop(o1);

        let o2 = bootstrap(&config).unwrap();
        assert_eq!(
            o2.replay_integrity_key.derive_hmac(b"persistence-test"),
            marker,
            "replay-integrity key must persist across restarts"
        );
    }

    // ── 7. concurrent_first_start_fails ─────────────────────────
    #[test]
    fn concurrent_first_start_fails() {
        use std::thread;

        let temp = TempDir::new().unwrap();
        let config1 = test_config(&temp);

        // First bootstrap holds the path lock
        let _o1 = bootstrap(&config1).unwrap();

        // Second bootstrap must fail (lock conflict)
        let temp_path = temp.path().to_path_buf();
        let handle = thread::spawn(move || {
            let config2 = {
                let defaults = BuiltInDefaults::new(&temp_path);
                ConfigurationSnapshot::from_defaults(&defaults)
            };
            bootstrap(&config2)
        });

        let result = handle.join().unwrap();
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("bootstrap error") || msg.contains("lock"),
            "expected lock conflict, got: {msg}"
        );
    }

    // ── 8. recovery_blocked_state ───────────────────────────────
    #[test]
    fn recovery_blocked_state() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        // Bootstrap once to create the DB
        let o1 = bootstrap(&config).unwrap();
        drop(o1);

        // Insert a synthetic event directly into the DB
        {
            let conn = schema::open_with_pragmas(&config.db_path).unwrap();
            // Insert into aggregate_streams so FK is satisfied
            conn.execute(
                "INSERT OR IGNORE INTO aggregate_streams
                 (aggregate_type, aggregate_id, current_version, created_at)
                 VALUES (1, x'00000000000000000000000000000042', 1, 0)",
                [],
            )
            .unwrap();
            // Insert an event
            conn.execute(
                "INSERT INTO events
                 (event_id, aggregate_type, aggregate_id, sequence, global_position,
                  timestamp, sensitivity, schema_version, command_id, idempotency_key,
                  actor, payload, integrity_digest, correlation_id, correlation_type,
                  integrity_profile)
                 VALUES
                 (randomblob(16), 1, x'00000000000000000000000000000042', 1, 1,
                  0, 0, 1, randomblob(16), x'01', x'02', x'03', randomblob(32),
                  randomblob(16), 1, 1)",
                [],
            )
            .unwrap();
            conn.close().unwrap();
        }

        // Now call enumerate_recovery_tasks — should be RecoveryBlocked
        use crate::recovery::enumerate_recovery_tasks;
        let conn = schema::open_with_pragmas(&config.db_path).unwrap();
        let state = enumerate_recovery_tasks(&conn).unwrap();
        assert_eq!(state, crate::recovery::RecoveryState::RecoveryBlocked);
    }

    #[test]
    fn prepared_first_activation_preflight_accepts_each_safe_sidecar_crash_window() {
        use gocode_api::{
            ExecutableIdentityV1, PendingFirstActivationV1, ProtectedRuntimeProfileV1,
            StableRuntimeBindingV1,
        };

        let authority = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 1,
        ];
        let pending = PendingFirstActivationV1::new(
            [
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 3,
            ],
            [0x10; 32],
            StableRuntimeBindingV1::new(
                authority,
                "local-owner",
                [
                    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 2,
                ],
                "gocode-ui-client/1",
                [0x20; 32],
                [0x30; 32],
            )
            .unwrap(),
            ExecutableIdentityV1::new([0x40; 32], [0x50; 32], 4_096).unwrap(),
            ProtectedRuntimeProfileV1::new(
                "gocode-bundled-runtime/1",
                1,
                "gocode-ui-client/1",
                [0x20; 32],
                [0x30; 32],
            )
            .unwrap(),
        )
        .unwrap();
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let launch = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 4,
        ];
        bootstrap_protected(&config, launch, [0x61; 32], Some(&pending), || {
            Err(DaemonError::Bootstrap(
                "protected launch authority expired".into(),
            ))
        })
        .expect_err("injected failure before consumption");

        let replay_key_path = Path::new(&config.replay_integrity_key_path);
        let authority_path = replay_key_path.with_file_name("local-session-authority-id");
        preflight_recoverable_first_activation_sidecars(&config, &authority)
            .expect("complete unconsumed sidecars");

        let connection = schema::open_with_pragmas(&config.db_path).unwrap();
        connection
            .execute(
                "DELETE FROM _daemon_info WHERE key = ?1",
                [SIDECAR_MIGRATION_MARKER_KEY],
            )
            .unwrap();
        drop(connection);
        preflight_recoverable_first_activation_sidecars(&config, &authority)
            .expect("crash before marker");

        fs::remove_file(&authority_path).unwrap();
        preflight_recoverable_first_activation_sidecars(&config, &authority)
            .expect("crash before authority sidecar");
        load_or_provision_local_session_authority(&authority_path, authority).unwrap();

        fs::remove_file(replay_key_path).unwrap();
        preflight_recoverable_first_activation_sidecars(&config, &authority)
            .expect("crash before replay-key sidecar");
        fs::remove_file(&authority_path).unwrap();
        preflight_recoverable_first_activation_sidecars(&config, &authority)
            .expect("crash before either sidecar");

        fs::write(replay_key_path, [0x7f; 7]).unwrap();
        assert!(preflight_recoverable_first_activation_sidecars(&config, &authority).is_err());
    }
}
