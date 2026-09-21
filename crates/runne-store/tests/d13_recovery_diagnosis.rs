//! D1.3 typed SQLite/WAL recovery diagnosis contract tests.
//!
//! Every scenario drives a real file-backed store inside `tempfile::tempdir()`;
//! `diagnose_managed_recovery` itself must stay read-only and never repair.

use std::path::Path;
use std::sync::Arc;

use runne_application::ports::RuntimeAuthorityId;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_security::SecretBroker;
use runne_store::schema::CURRENT_SCHEMA_VERSION;
use runne_store::schema::recovery_diagnosis::{StoreRecoveryDiagnosis, diagnose_managed_recovery};
use runne_store::store::StoreTransaction;

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn open_store(database_path: &str) -> StoreTransaction {
    StoreTransaction::open(
        database_path,
        RuntimeAuthorityId("d13-recovery-diagnosis".into()),
        available_guard(),
    )
    .unwrap()
}

fn database_directory(tag: &str) -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon.join(format!("{tag}.sqlite"));
    (directory, path.to_str().unwrap().to_owned())
}

fn diagnose(path: &str) -> StoreRecoveryDiagnosis {
    diagnose_managed_recovery(Path::new(path))
}

#[test]
fn healthy_store_after_clean_close_and_reopen_diagnoses_ready() {
    let (_directory, database_path) = database_directory("d13-diagnosis-healthy");
    drop(open_store(&database_path));
    assert_eq!(diagnose(&database_path), StoreRecoveryDiagnosis::Ready);
    // A normal closed store keeps its checkpointed `-wal`/`-shm`; production
    // restarts it through the validated writer reopen, so diagnosis must too.
    let reopened = runne_store::schema::reopen_managed_connection_validated(
        Path::new(&database_path),
        runne_store::schema::ConnectionMode::ValidatedReopen,
        |_| Ok(()),
    )
    .unwrap();
    drop(reopened);
    assert_eq!(diagnose(&database_path), StoreRecoveryDiagnosis::Ready);
}

#[test]
fn corrupted_main_database_diagnoses_integrity_check_failed() {
    let (_directory, database_path) = database_directory("d13-diagnosis-corrupt");
    drop(open_store(&database_path));
    checkpoint_and_remove_sidecars(&database_path);
    corrupt_main_database(&database_path);
    assert_eq!(
        diagnose(&database_path),
        StoreRecoveryDiagnosis::IntegrityCheckFailed
    );
}

/// Overwrites one mid-file page slice with garbage: the header and schema
/// catalog on page 1 stay readable, so classification passes and the failure
/// is attributed by `PRAGMA integrity_check`.
fn corrupt_main_database(database_path: &str) {
    let mut bytes = std::fs::read(database_path).unwrap();
    assert!(
        bytes.len() >= 5 * 4096,
        "fixture store is unexpectedly small"
    );
    let start = 3 * 4096;
    for byte in &mut bytes[start..start + 32] {
        *byte = 0xC3;
    }
    std::fs::write(database_path, bytes).unwrap();
}

/// Makes the main database self-contained the way a writer-only close would:
/// checkpoint every committed WAL frame, then remove the sidecars (removing a
/// checkpointed WAL is a legal recovery state).
fn checkpoint_and_remove_sidecars(database_path: &str) {
    let connection = rusqlite::Connection::open(database_path).unwrap();
    connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .unwrap();
    drop(connection);
    for suffix in ["-wal", "-shm"] {
        let sidecar = std::path::PathBuf::from(format!("{database_path}{suffix}"));
        if sidecar.exists() {
            std::fs::remove_file(&sidecar).unwrap();
        }
    }
}

#[test]
fn zero_byte_database_diagnoses_without_opening() {
    let directory = tempfile::tempdir().unwrap();
    let path = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("zero.sqlite")
    };
    std::fs::write(&path, b"").unwrap();
    assert_eq!(
        diagnose_managed_recovery(&path),
        StoreRecoveryDiagnosis::ZeroByteDatabase
    );
}

#[test]
fn removed_wal_sidecars_after_clean_close_stay_ready() {
    let (_directory, database_path) = database_directory("d13-diagnosis-no-sidecars");
    drop(open_store(&database_path));
    checkpoint_and_remove_sidecars(&database_path);
    assert_eq!(diagnose(&database_path), StoreRecoveryDiagnosis::Ready);
    // A read-only open of a WAL database MAY materialize the `-shm` index and
    // an empty `-wal`; the assertion deliberately accepts both outcomes:
    // `unwrap_or(0)` covers an absent `-wal` too, which equally proves zero
    // frames were written, and any `-wal` a read-only connection creates is
    // always 0 bytes (the WAL header is only written when frames commit).
    let wal_len = std::fs::metadata(format!("{database_path}-wal"))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    assert_eq!(wal_len, 0);
}

#[test]
fn downgraded_schema_version_diagnoses_schema_version_mismatch() {
    let (_directory, database_path) = database_directory("d13-diagnosis-downgrade");
    // Build a real released-v23 store: classification admits it, but the
    // startup gate sees an older durable schema version than this build.
    let connection = runne_store::schema::open_managed_connection(
        Path::new(&database_path),
        runne_store::schema::ConnectionMode::Writer,
    )
    .unwrap();
    runne_store::schema::apply_migrations_through_v23_for_test(&connection).unwrap();
    drop(connection);
    assert_eq!(
        diagnose(&database_path),
        StoreRecoveryDiagnosis::SchemaVersionMismatch {
            found: 23,
            expected: u32::try_from(CURRENT_SCHEMA_VERSION).unwrap(),
        }
    );
}

#[test]
fn garbage_file_from_byte_zero_diagnoses_unavailable() {
    let directory = tempfile::tempdir().unwrap();
    let path = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("garbage.sqlite")
    };
    let garbage = vec![0xC3_u8; 2048];
    std::fs::write(&path, garbage).unwrap();
    assert_eq!(
        diagnose_managed_recovery(&path),
        StoreRecoveryDiagnosis::Unavailable
    );
}

#[test]
fn diagnosis_never_mutates_the_main_database_file() {
    let (_directory, database_path) = database_directory("d13-diagnosis-read-only");
    drop(open_store(&database_path));
    let before = std::fs::read(&database_path).unwrap();
    assert_eq!(diagnose(&database_path), StoreRecoveryDiagnosis::Ready);
    let after = std::fs::read(&database_path).unwrap();
    assert_eq!(before, after);
}
