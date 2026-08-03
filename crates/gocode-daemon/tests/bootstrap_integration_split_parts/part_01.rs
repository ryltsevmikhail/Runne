use gocode_daemon::bootstrap::{BootstrapOutcome, StartupMode, bootstrap};
use gocode_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use gocode_daemon::lock::LockSet;
use gocode_daemon::recovery::{RecoveryState, enumerate_recovery_tasks};
use gocode_store::schema;
use rusqlite::Connection;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
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

/// Get the replay-integrity key path from a config.
fn replay_key_path(config: &ConfigurationSnapshot) -> PathBuf {
    PathBuf::from(&config.replay_integrity_key_path)
}

fn local_session_authority_path(config: &ConfigurationSnapshot) -> PathBuf {
    replay_key_path(config).with_file_name("local-session-authority-id")
}

fn remove_sidecar_migration_marker(config: &ConfigurationSnapshot) {
    let connection = schema::open_with_pragmas(&config.db_path).unwrap();
    connection
        .execute(
            "DELETE FROM _daemon_info WHERE key = 'local_session_sidecars_v1'",
            [],
        )
        .unwrap();
}

/// Extract daemon_dir from db_path.
fn daemon_dir(db: &Path) -> &std::path::Path {
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

// ── 1. first_start_creates_db_and_replay_key ─────────────────────────
#[test]
fn first_start_creates_db_and_replay_key() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    let outcome = bootstrap(&config).unwrap();

    assert_outcome(&outcome, false, StartupMode::FirstStart);
    assert!(db_path(&config).exists(), "DB file must exist");
    assert!(
        replay_key_path(&config).exists(),
        "replay-integrity key must exist"
    );
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

// ── 6. restart_with_existing_replay_key_loads_correctly ─────────────
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
