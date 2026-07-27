//! Integration tests for daemon bootstrap (Phase 4, Task 5).
//!
//! Covers all six crash states plus concurrent and recovery scenarios.

use gocode_daemon::bootstrap::{BootstrapOutcome, StartupMode, bootstrap};
use gocode_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use gocode_daemon::lock::LockSet;
use gocode_daemon::recovery::{RecoveryState, enumerate_recovery_tasks};
use gocode_store::schema;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

// ── Helpers ──────────────────────────────────────────────────────────

/// Build a `ConfigurationSnapshot` rooted at a temp dir.
fn test_config(temp: &TempDir) -> ConfigurationSnapshot {
    let defaults = BuiltInDefaults::new(temp.path());
    ConfigurationSnapshot::from_defaults(&defaults)
}

/// Get the db_path as a PathBuf from a config.
fn db_path(config: &ConfigurationSnapshot) -> PathBuf {
    PathBuf::from(&config.db_path)
}

/// Get the token_path as a PathBuf from a config.
fn token_path(config: &ConfigurationSnapshot) -> PathBuf {
    PathBuf::from(&config.token_path)
}

/// Extract daemon_dir from db_path.
fn daemon_dir(db: &PathBuf) -> &std::path::Path {
    db.parent().unwrap()
}

/// Extract runtime_dir (parent of daemon_dir).
fn runtime_dir(daemon: &std::path::Path) -> &std::path::Path {
    daemon.parent().unwrap()
}

/// Assert outcome state matches expectations.
fn assert_outcome(outcome: &BootstrapOutcome, db_existed: bool, mode: StartupMode) {
    assert_eq!(outcome.db_existed, db_existed);
    assert_eq!(outcome.startup_mode, mode);
}

// ── 1. first_start_creates_db_and_token ─────────────────────────────
#[test]
fn first_start_creates_db_and_token() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    let outcome = bootstrap(&config).unwrap();

    assert_outcome(&outcome, false, StartupMode::FirstStart);
    assert!(db_path(&config).exists(), "DB file must exist");
    assert!(token_path(&config).exists(), "token file must exist");
    // file_lock only acquired for existing DBs (no hardlink risk on fresh create)
    assert!(
        outcome.locks.authority_lock.is_some(),
        "authority lock must be held"
    );
}

// ── 2. restart_reuses_existing_db ───────────────────────────────────
#[test]
fn restart_reuses_existing_db() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    // First bootstrap
    let o1 = bootstrap(&config).unwrap();
    assert_outcome(&o1, false, StartupMode::FirstStart);
    let aid1 = o1.authority_id;
    drop(o1);

    // Second bootstrap finds existing DB
    let o2 = bootstrap(&config).unwrap();
    assert_outcome(&o2, true, StartupMode::Restart);
    assert_eq!(
        o2.authority_id, aid1,
        "authority must persist across restarts"
    );
}

// ── 3. crash_before_metadata_publish_is_repaired ────────────────────
#[test]
fn crash_before_metadata_publish_is_repaired() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    // Full bootstrap to create DB + authority
    let o1 = bootstrap(&config).unwrap();
    let aid = o1.authority_id;
    drop(o1);

    // Simulate crash: clear lock metadata
    let db = db_path(&config);
    let dd = daemon_dir(&db).to_path_buf();
    let rt = runtime_dir(&dd).to_path_buf();

    {
        let locks = LockSet::acquire_path(&db, &rt).unwrap();
        // Truncate metadata to 0 bytes (no daemon wrote it)
        let f = locks.path_lock.file();
        f.set_len(0).unwrap();
        f.sync_all().unwrap();
    }

    // Bootstrap again — must repair metadata
    let o2 = bootstrap(&config).unwrap();
    assert_outcome(&o2, true, StartupMode::Restart);
    assert_eq!(
        o2.authority_id, aid,
        "authority must be unchanged after repair"
    );
}

// ── 4. authority_mismatch_causes_error ──────────────────────────────
#[test]
fn authority_mismatch_causes_error() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    // Full bootstrap to create state
    let o1 = bootstrap(&config).unwrap();
    drop(o1);

    // Write a different (wrong) authority into lock metadata
    let db = db_path(&config);
    let dd = daemon_dir(&db).to_path_buf();
    let rt = runtime_dir(&dd).to_path_buf();
    let wrong_aid: [u8; 16] = [0xDE; 16];

    {
        let locks = LockSet::acquire_path(&db, &rt).unwrap();
        locks.write_metadata(&wrong_aid).unwrap();
    }

    // Bootstrap must fail
    let result = bootstrap(&config);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("authority mismatch") || msg.contains("bootstrap error"),
        "expected authority mismatch error, got: {msg}"
    );
}

// ── 5. published_authority_without_db_causes_error ──────────────────
#[test]
fn published_authority_without_db_causes_error() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    let db = db_path(&config);
    let dd = daemon_dir(&db).to_path_buf();
    let rt = runtime_dir(&dd).to_path_buf();

    // Create daemon dir + write metadata without creating the DB
    fs::create_dir_all(&dd).unwrap();

    let fake_aid: [u8; 16] = [0xFA; 16];
    {
        // Lock requires the DB file to exist (for canonicalisation)
        fs::File::create(&db).unwrap();
        let locks = LockSet::acquire_path(&db, &rt).unwrap();
        locks.write_metadata(&fake_aid).unwrap();
        // Drop lock — metadata is on disk, but we'll delete the DB
    }
    // Remove DB file, leaving metadata intact
    fs::remove_file(&db).unwrap();

    // Bootstrap must fail — authority metadata exists without Event Log
    let result = bootstrap(&config);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("bootstrap error") || msg.contains("authority"),
        "expected authority-without-db error, got: {msg}"
    );
}

// ── 6. restart_with_existing_token_loads_correctly ──────────────────
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

// ── 7. concurrent_first_start_fails ─────────────────────────────────
#[test]
fn concurrent_first_start_fails() {
    use std::thread;

    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    // First bootstrap holds all locks
    let _o1 = bootstrap(&config).unwrap();

    // Second bootstrap on the same path must fail
    let temp_path = temp.path().to_path_buf();
    let handle = thread::spawn(move || {
        let defaults = BuiltInDefaults::new(&temp_path);
        let config2 = ConfigurationSnapshot::from_defaults(&defaults);
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

// ── 8. recovery_blocked_state ───────────────────────────────────────
#[test]
fn recovery_blocked_state() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    // Bootstrap to create the DB
    let o1 = bootstrap(&config).unwrap();
    drop(o1);

    // Insert a synthetic event through a raw connection
    let conn = schema::open_with_pragmas(&config.db_path).unwrap();

    // Need to satisfy FK constraints
    conn.execute(
        "INSERT OR IGNORE INTO aggregate_streams
         (aggregate_type, aggregate_id, current_version, created_at)
         VALUES (1, x'00000000000000000000000000000042', 1, 0)",
        [],
    )
    .unwrap();

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

    let state = enumerate_recovery_tasks(&conn).unwrap();
    assert_eq!(state, RecoveryState::RecoveryBlocked);
}

// ── 9. empty_db_recovery_ready ──────────────────────────────────────
#[test]
fn empty_db_recovery_ready() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    // Fresh bootstrap — DB should be empty of events
    let outcome = bootstrap(&config).unwrap();

    let state = enumerate_recovery_tasks(&outcome.db_conn).unwrap();
    assert_eq!(state, RecoveryState::Ready);
}

// ── 10. token_missing_for_existing_db_is_fatal ──────────────────────
#[test]
fn token_missing_for_existing_db_is_fatal() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    // Bootstrap once to create DB + token
    let o1 = bootstrap(&config).unwrap();
    drop(o1);

    // Delete the token file
    fs::remove_file(token_path(&config)).unwrap();

    // Bootstrap must fail — DB exists but token is missing
    let result = bootstrap(&config);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("token") || msg.contains("missing"),
        "expected token-missing error, got: {msg}"
    );
}
