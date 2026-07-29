//! Integration tests for the three-layer lock system.
//!
//! Covers: path lock acquisition, conflict detection, metadata I/O,
//! file identity lock, authority lock, malformed metadata detection,
//! lock release on drop, concurrent conflict, and hardlink identity.

use gocode_daemon::lock::{LockSet, MetadataSnapshot};
use std::fs;
use std::io::Write;
use tempfile::TempDir;

/// Helper: create a temp dir with a `gocode-daemon` subdirectory.
fn runtime_dir() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("gocode-daemon")).unwrap();
    dir
}

/// Helper: create a dummy file to act as a DB path.
fn dummy_db(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("event-log.db");
    fs::File::create(&path).unwrap();
    path
}

// ── 1. acquire_path_creates_lock ──────────────────────────────────
#[test]
fn acquire_path_creates_lock() {
    let rt = runtime_dir();
    let db = dummy_db(&rt);

    let locks = LockSet::acquire_path(&db, rt.path()).unwrap();

    // The lock file must exist in runtime_dir/gocode-daemon/
    let canonical = fs::canonicalize(&db).unwrap();
    let hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(canonical.to_str().unwrap().as_bytes()))
    };
    let lock_path = rt
        .path()
        .join("gocode-daemon")
        .join(format!("path-{hash}.lock"));
    assert!(
        lock_path.exists(),
        "lock file should exist at {lock_path:?}"
    );

    // Metadata should be Empty for a fresh lock
    let snap = locks.read_metadata_snapshot().unwrap();
    assert_eq!(snap, MetadataSnapshot::Empty);
}

// ── 2. acquire_path_conflict ──────────────────────────────────────
#[test]
fn acquire_path_conflict() {
    let rt = runtime_dir();
    let db = dummy_db(&rt);

    let _locks1 = LockSet::acquire_path(&db, rt.path()).unwrap();
    let result2 = LockSet::acquire_path(&db, rt.path());

    assert!(result2.is_err(), "second acquire on same path must fail");
    let msg = format!("{}", result2.unwrap_err());
    assert!(
        msg.contains("lock error") || msg.contains("WouldBlock") || msg.contains("resource"),
        "expected lock conflict, got: {msg}"
    );
}

// ── 3. read_metadata_empty ────────────────────────────────────────
#[test]
fn read_metadata_empty() {
    let rt = runtime_dir();
    let db = dummy_db(&rt);
    let locks = LockSet::acquire_path(&db, rt.path()).unwrap();

    let snap = locks.read_metadata_snapshot().unwrap();
    assert_eq!(snap, MetadataSnapshot::Empty);
}

// ── 4. write_and_read_metadata ────────────────────────────────────
#[test]
fn write_and_read_metadata() {
    let rt = runtime_dir();
    let db = dummy_db(&rt);
    let locks = LockSet::acquire_path(&db, rt.path()).unwrap();

    let aid: [u8; 16] = [0xAA; 16];
    locks.write_metadata(&aid).unwrap();

    let snap = locks.read_metadata_snapshot().unwrap();
    assert_eq!(snap, MetadataSnapshot::Valid { authority_id: aid });
}

// ── 5. metadata_different_paths_independent ───────────────────────
#[test]
fn metadata_different_paths_independent() {
    let rt = runtime_dir();

    let db1 = rt.path().join("db1.db");
    fs::File::create(&db1).unwrap();
    let db2 = rt.path().join("db2.db");
    fs::File::create(&db2).unwrap();

    let locks1 = LockSet::acquire_path(&db1, rt.path()).unwrap();
    let locks2 = LockSet::acquire_path(&db2, rt.path()).unwrap();

    assert_eq!(
        locks1.read_metadata_snapshot().unwrap(),
        MetadataSnapshot::Empty
    );
    assert_eq!(
        locks2.read_metadata_snapshot().unwrap(),
        MetadataSnapshot::Empty
    );
}

// ── 6. file_identity_lock ─────────────────────────────────────────
#[test]
fn file_identity_lock() {
    let rt = runtime_dir();
    let db = dummy_db(&rt);

    let mut locks = LockSet::acquire_path(&db, rt.path()).unwrap();
    let file = fs::File::open(&db).unwrap();

    locks
        .acquire_file_lock(&file, rt.path())
        .expect("file identity lock acquisition should succeed");
    assert!(locks.file_lock.is_some());
}

// ── 7. authority_lock ─────────────────────────────────────────────
#[test]
fn authority_lock() {
    let rt = runtime_dir();
    let db = dummy_db(&rt);

    let mut locks = LockSet::acquire_path(&db, rt.path()).unwrap();
    let aid: [u8; 16] = [0xBB; 16];

    locks
        .acquire_authority_lock(&aid, rt.path())
        .expect("authority lock acquisition should succeed");
    assert!(locks.authority_lock.is_some());
}

// ── 8. malformed_metadata_detected ────────────────────────────────
#[test]
fn malformed_metadata_detected() {
    let rt = runtime_dir();
    let db = dummy_db(&rt);
    let locks = LockSet::acquire_path(&db, rt.path()).unwrap();

    // Write garbage (25 bytes of 0xFF) to simulate torn write
    use std::io::Seek;
    use std::io::SeekFrom;
    let mut f = locks.path_lock.file();
    f.set_len(0).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f.write_all(&[0xFFu8; 25]).unwrap();
    f.sync_all().unwrap();

    let snap = locks.read_metadata_snapshot().unwrap();
    assert_eq!(snap, MetadataSnapshot::Malformed);
}

// ── 9. lock_released_on_drop ──────────────────────────────────────
#[test]
fn lock_released_on_drop() {
    let rt = runtime_dir();
    let db = dummy_db(&rt);

    {
        let _locks = LockSet::acquire_path(&db, rt.path()).unwrap();
        // Lock held here
    }
    // Lock released — should be able to acquire again
    let result = LockSet::acquire_path(&db, rt.path());
    assert!(result.is_ok(), "lock must be released on drop");
}

// ── 10. concurrent_lock_conflict ──────────────────────────────────
#[test]
fn concurrent_lock_conflict() {
    use std::thread;

    let rt = runtime_dir();
    let db = dummy_db(&rt);

    let _locks = LockSet::acquire_path(&db, rt.path()).unwrap();

    let rt_path = rt.path().to_path_buf();
    let db_clone = db.clone();

    let handle = thread::spawn(move || LockSet::acquire_path(&db_clone, &rt_path));

    let result = handle.join().unwrap();
    assert!(result.is_err(), "concurrent acquire on same path must fail");
}

// ── 11. hardlink_same_identity ────────────────────────────────────
#[test]
fn hardlink_same_identity() {
    let rt = TempDir::new().unwrap();
    let path_a = rt.path().join("a.db");
    let path_b = rt.path().join("b.db");

    fs::File::create(&path_a).unwrap();
    fs::hard_link(&path_a, &path_b).unwrap();

    let fa = fs::File::open(&path_a).unwrap();
    let fb = fs::File::open(&path_b).unwrap();

    // Use the platform_file_identity via the lock module's public API.
    // We access it indirectly: acquire_file_lock on the same file should
    // use the same lock path.
    // Instead, we rely on the module test `hardlink_same_identity` inside lock.rs
    // which tests `platform_file_identity` directly.
    // Here we do a cross-test: acquire file lock on both files — they should
    // conflict because they have the same identity.

    let rt_lock = runtime_dir();
    let mut locks_a = LockSet::acquire_path(&path_a, rt_lock.path()).unwrap();
    locks_a.acquire_file_lock(&fa, rt_lock.path()).unwrap();

    // Opening the hardlink (same file identity) and trying to acquire
    // should fail because the same file-identity lock is held.
    let mut locks_b = LockSet::acquire_path(&path_b, rt_lock.path()).unwrap();
    let result = locks_b.acquire_file_lock(&fb, rt_lock.path());
    assert!(
        result.is_err(),
        "hardlinked files have same identity — file lock must conflict"
    );
}
