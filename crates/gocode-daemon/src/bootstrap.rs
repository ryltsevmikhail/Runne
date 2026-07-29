//! Bootstrap subsystem — full daemon startup sequence.
//!
//! Implements ADR-0014 bootstrap sequence:
//! acquire three-layer locks, provision or load the daemon token,
//! open the SQLite database, apply schema migrations, reconcile
//! authority metadata, purge stale replay subscriptions, and
//! detect recovery tasks.
//!
//! ## Lock acquisition order
//!
//! 1. Provisional path lock — before DB open, serialises first-start
//!    and token side effects.
//! 2. File identity lock — after DB verify handle (no-follow open).
//! 3. Authority lock — after reading/generating `_authority` from schema v8 DB.

use crate::config::ConfigurationSnapshot;
use crate::error::DaemonError;
use crate::launch_identity::LaunchIdentity;
use crate::lock::{LockSet, MetadataSnapshot};
use crate::token::{DaemonToken, TokenManager};
use std::fs;
use std::path::{Path, PathBuf};

use gocode_store::schema;

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
/// the token is loaded or provisioned.
pub struct BootstrapOutcome {
    /// All three locks held (path, file, authority).
    pub locks: LockSet,
    /// Open writable SQLite connection with schema applied.
    pub db_conn: rusqlite::Connection,
    /// Authority ID from the `_authority` table.
    pub authority_id: [u8; 16],
    /// Whether the DB file existed before this bootstrap.
    pub db_existed: bool,
    /// How the daemon started.
    pub startup_mode: StartupMode,
    /// Fresh TLS and bootstrap identity for this daemon launch.
    pub launch_identity: LaunchIdentity,
    /// Durable positive generation allocated for this launch.
    pub launch_generation: u64,
    /// Provisioned or loaded daemon token.
    pub token: DaemonToken,
}

impl std::fmt::Debug for BootstrapOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapOutcome")
            .field("locks", &self.locks)
            .field("db_conn", &"<Connection>")
            .field("authority_id", &hex::encode(self.authority_id))
            .field("db_existed", &self.db_existed)
            .field("startup_mode", &self.startup_mode)
            .field("launch_identity", &self.launch_identity)
            .field("launch_generation", &self.launch_generation)
            .field("token", &self.token)
            .finish()
    }
}

// ── Public API ────────────────────────────────────────────────────────

/// Full bootstrap sequence.
///
/// Returns a `BootstrapOutcome` with all acquired resources, or a
/// `DaemonError` for fatal startup failures (missing token, DB change
/// under live lock, authority without Event Log, etc.).
pub fn bootstrap(config: &ConfigurationSnapshot) -> Result<BootstrapOutcome, DaemonError> {
    let db_path = PathBuf::from(&config.db_path);
    let token_path = PathBuf::from(&config.token_path);

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

    // ── Step 8: token lifecycle ─────────────────────────────────────
    let token = load_or_provision_token(&token_path, startup_mode, db_existed)?;

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
    let launch_generation = schema::next_launch_generation(&db_conn)
        .map_err(|_| DaemonError::Bootstrap("allocate launch generation: corrupt state".into()))?;
    let launch_identity = LaunchIdentity::generate(launch_generation)
        .map_err(|_| DaemonError::Bootstrap("generate launch TLS identity".into()))?;

    // ── Step 12: authority ID ───────────────────────────────────────
    let (authority_id, db_authority_after) =
        acquire_authority(db_existed, &db_conn, &mut locks, &runtime_dir)?;

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
        db_existed,
        startup_mode,
        launch_identity,
        launch_generation,
        token,
    })
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Ensure `dir` exists with secure permissions (0700).
fn ensure_dir_secured(dir: &Path) -> Result<(), DaemonError> {
    fs::create_dir_all(dir)
        .map_err(|e| DaemonError::Bootstrap(format!("cannot create {dir:?}: {e}")))?;
    schema::secure_dir_permissions(dir)
        .map_err(|e| DaemonError::Bootstrap(format!("cannot secure {dir:?}: {e}")))
}

/// Load or provision the daemon token based on startup scenario.
fn load_or_provision_token(
    token_path: &Path,
    startup_mode: StartupMode,
    db_existed: bool,
) -> Result<DaemonToken, DaemonError> {
    let token_exists = token_path.exists();

    match (startup_mode, token_exists, db_existed) {
        // First start with no existing token → provision
        (StartupMode::FirstStart, false, _) => TokenManager::provision(token_path),

        // Crash recovery: DB missing but token exists from prior partial bootstrap
        (StartupMode::FirstStart, true, _) => TokenManager::load(token_path),

        // Normal restart: DB exists, load existing token
        (StartupMode::Restart, true, _) => TokenManager::load(token_path),

        // DB exists but token file is missing — fatal (exit 2 equivalent)
        (StartupMode::Restart, false, true) => Err(DaemonError::Bootstrap(
            "database exists but token file is missing".into(),
        )),

        // Should be unreachable (Restart with no DB is FirstStart)
        (StartupMode::Restart, false, false) => Err(DaemonError::Bootstrap(
            "invalid state: restart with no database".into(),
        )),

        // Recovered mode is set by the recovery subsystem only
        (StartupMode::Recovered, _, _) => Err(DaemonError::Bootstrap(
            "recovered mode is not yet implemented".into(),
        )),
    }
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
) -> Result<([u8; 16], Option<[u8; 16]>), DaemonError> {
    let db_authority = schema::read_authority_id(conn)
        .map_err(|e| DaemonError::Bootstrap(format!("read authority: {e}")))?;

    match (db_existed, db_authority) {
        // New DB — generate fresh authority
        (false, None) => {
            let aid = schema::generate_authority_id();
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

    // ── 1. first_start_creates_db_and_token ─────────────────────
    #[test]
    fn first_start_creates_db_and_token() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        let outcome = bootstrap(&config).unwrap();

        assert!(!outcome.db_existed);
        assert_eq!(outcome.startup_mode, StartupMode::FirstStart);
        assert!(PathBuf::from(&config.db_path).exists());
        assert!(PathBuf::from(&config.token_path).exists());
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

    // ── 6. restart_with_existing_token_loads_correctly ──────────
    #[test]
    fn restart_with_existing_token_loads_correctly() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        let o1 = bootstrap(&config).unwrap();
        let token1 = o1.token.clone();
        drop(o1);

        let o2 = bootstrap(&config).unwrap();
        assert_eq!(o2.token, token1, "token must persist across restarts");
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
}
