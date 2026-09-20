use std::path::{Path, PathBuf};

use runne_provider::{
    DispatchAttemptId, ScannerTerminalDisposition, ScannerUncertainReason, TailBinding,
};
use runne_runtime::provider_redaction::ScannerRecoveryPersistence;
use runne_store::provider::SqliteProviderRecoveryStore;
use rusqlite::Connection;

const AUTHORITY: [u8; 16] = [0x41; 16];

fn fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::Builder::new().prefix(name).tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    (directory, PathBuf::from("runne-daemon/event-log.sqlite"))
}

fn base_path(directory: &tempfile::TempDir, relative: &Path) -> PathBuf {
    directory.path().join(relative)
}

fn sidecar_path(base: &Path) -> PathBuf {
    PathBuf::from(format!("{}.scanner-recovery", base.display()))
}

#[derive(Debug, PartialEq, Eq)]
struct DurableFileProof {
    bytes: Vec<u8>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

fn durable_file_proof(path: &Path) -> DurableFileProof {
    #[cfg(unix)]
    let metadata = std::fs::metadata(path).unwrap();
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;
    DurableFileProof {
        bytes: std::fs::read(path).unwrap(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
    }
}

fn durable_shape(path: &Path) -> (i64, Vec<(String, String)>, Vec<Vec<u8>>) {
    let connection = Connection::open(path).unwrap();
    let version = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let catalog = connection
        .prepare(
            "SELECT name, sql FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let identities = connection
        .prepare(
            "SELECT authority_id FROM scanner_recovery_schema
             WHERE id = 1 ORDER BY authority_id",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    (version, catalog, identities)
}

#[test]
fn scanner_sidecar_create_and_authority_bound_reopen_preserve_record() {
    let (directory, relative) = fixture("scanner-sidecar-reopen");
    let base = base_path(&directory, &relative);
    let attempt = DispatchAttemptId::from_bytes([3; 16]);
    let binding = TailBinding::new(attempt, 7, 1, 1, 1, 0).unwrap();
    let store = SqliteProviderRecoveryStore::open(&base, AUTHORITY).unwrap();
    store
        .commit_terminal(
            binding,
            ScannerTerminalDisposition::Uncertain(ScannerUncertainReason::SecretDetected),
        )
        .unwrap();
    drop(store);

    let reopened = SqliteProviderRecoveryStore::open(&base, AUTHORITY).unwrap();
    assert_eq!(
        reopened.load(attempt).unwrap().unwrap().disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::SecretDetected
        ))
    );
}

#[test]
fn scanner_sidecar_hot_wal_crash_window_reopens_with_same_authority() {
    let (directory, relative) = fixture("scanner-sidecar-hot-wal");
    let base = base_path(&directory, &relative);
    let retained = SqliteProviderRecoveryStore::open(&base, AUTHORITY).unwrap();
    assert!(
        sidecar_path(&base)
            .with_extension("scanner-recovery-wal")
            .exists()
    );
    let reopened = SqliteProviderRecoveryStore::open(&base, AUTHORITY).unwrap();
    drop((retained, reopened));
}

#[test]
fn scanner_sidecar_rejects_stale_authority_without_mutation() {
    let (directory, relative) = fixture("scanner-sidecar-stale-authority");
    let base = base_path(&directory, &relative);
    drop(SqliteProviderRecoveryStore::open(&base, AUTHORITY).unwrap());
    let sidecar = sidecar_path(&base);
    let before = durable_shape(&sidecar);
    assert!(SqliteProviderRecoveryStore::open(&base, [0x42; 16]).is_err());
    assert_eq!(durable_shape(&sidecar), before);
}

#[test]
fn scanner_sidecar_rejects_future_schema_without_mutation() {
    let (directory, relative) = fixture("scanner-sidecar-future");
    let base = base_path(&directory, &relative);
    drop(SqliteProviderRecoveryStore::open(&base, AUTHORITY).unwrap());
    let sidecar = sidecar_path(&base);
    Connection::open(&sidecar)
        .unwrap()
        .pragma_update(None, "user_version", 3_i64)
        .unwrap();
    let before = durable_shape(&sidecar);
    assert!(SqliteProviderRecoveryStore::open(&base, AUTHORITY).is_err());
    assert_eq!(durable_shape(&sidecar), before);
}

#[test]
fn scanner_sidecar_rejects_old_schema_without_mutation() {
    let (directory, relative) = fixture("scanner-sidecar-old");
    let base = base_path(&directory, &relative);
    drop(SqliteProviderRecoveryStore::open(&base, AUTHORITY).unwrap());
    let sidecar = sidecar_path(&base);
    let connection = Connection::open(&sidecar).unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints=ON; PRAGMA user_version=1;")
        .unwrap();
    connection
        .execute(
            "UPDATE scanner_recovery_schema SET schema_version=1 WHERE id=1",
            [],
        )
        .unwrap();
    drop(connection);
    let before = durable_shape(&sidecar);
    assert!(SqliteProviderRecoveryStore::open(&base, AUTHORITY).is_err());
    assert_eq!(durable_shape(&sidecar), before);
}

#[test]
fn scanner_sidecar_rejects_unknown_catalog_without_mutation() {
    let (directory, relative) = fixture("scanner-sidecar-unknown");
    let base = base_path(&directory, &relative);
    drop(SqliteProviderRecoveryStore::open(&base, AUTHORITY).unwrap());
    let sidecar = sidecar_path(&base);
    Connection::open(&sidecar)
        .unwrap()
        .execute_batch("CREATE TABLE unknown_extension (value INTEGER);")
        .unwrap();
    let before = durable_shape(&sidecar);
    assert!(SqliteProviderRecoveryStore::open(&base, AUTHORITY).is_err());
    assert_eq!(durable_shape(&sidecar), before);
}

#[test]
fn scanner_sidecar_rejects_unknown_view_without_file_mutation() {
    let (directory, relative) = fixture("scanner-sidecar-unknown-view");
    let base = base_path(&directory, &relative);
    drop(SqliteProviderRecoveryStore::open(&base, AUTHORITY).unwrap());
    let sidecar = sidecar_path(&base);
    Connection::open(&sidecar)
        .unwrap()
        .execute_batch(
            "CREATE VIEW unknown_recovery_view AS
             SELECT attempt_id FROM provider_scanner_recovery;",
        )
        .unwrap();
    let before = durable_file_proof(&sidecar);
    assert!(SqliteProviderRecoveryStore::open(&base, AUTHORITY).is_err());
    assert_eq!(durable_file_proof(&sidecar), before);
}

#[test]
fn scanner_sidecar_rejects_unknown_trigger_without_file_mutation() {
    let (directory, relative) = fixture("scanner-sidecar-unknown-trigger");
    let base = base_path(&directory, &relative);
    drop(SqliteProviderRecoveryStore::open(&base, AUTHORITY).unwrap());
    let sidecar = sidecar_path(&base);
    Connection::open(&sidecar)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER unknown_recovery_trigger
             AFTER INSERT ON provider_scanner_recovery
             BEGIN SELECT 1; END;",
        )
        .unwrap();
    let before = durable_file_proof(&sidecar);
    assert!(SqliteProviderRecoveryStore::open(&base, AUTHORITY).is_err());
    assert_eq!(durable_file_proof(&sidecar), before);
}

#[test]
fn scanner_sidecar_rejects_corrupt_identity_without_mutation() {
    let (directory, relative) = fixture("scanner-sidecar-corrupt");
    let base = base_path(&directory, &relative);
    drop(SqliteProviderRecoveryStore::open(&base, AUTHORITY).unwrap());
    let sidecar = sidecar_path(&base);
    Connection::open(&sidecar)
        .unwrap()
        .execute("DELETE FROM scanner_recovery_schema WHERE id = 1", [])
        .unwrap();
    let before = durable_shape(&sidecar);
    assert!(SqliteProviderRecoveryStore::open(&base, AUTHORITY).is_err());
    assert_eq!(durable_shape(&sidecar), before);
}
