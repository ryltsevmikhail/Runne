use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use gocode_application::{
    ports::{CommitError, RuntimeAuthorityId, StorageFailureKind},
    prohibited_content::ProhibitedContentPort,
    security::atomic_transaction::AtomicTransactionError,
};
use gocode_security::SecretBroker;
use gocode_store::schema::{
    SchemaOpenDiagnostic, apply_migrations, open_with_pragmas, preflight_existing_file,
};
use gocode_store::{
    atomic_pre_effect::SqliteAtomicPreEffectStore,
    migration_store::SqliteMigrationControlStore,
    store::StoreTransaction,
    verification::{evidence_store::SqliteEvidenceStore, intent_store::SqliteIntentStore},
};
use rusqlite::{Connection, OpenFlags};

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn candidate_database(name: &str) -> PathBuf {
    candidate_database_version(name, 9)
}

fn candidate_database_version(name: &str, version: i64) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "gocode-schema-preflight-{name}-{}-{nonce}.sqlite",
        std::process::id()
    ));
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
             INSERT INTO schema_version (version) VALUES (9);
             CREATE TABLE candidate_data (value TEXT NOT NULL);
             INSERT INTO candidate_data VALUES ('unchanged');",
        )
        .unwrap();
    connection
        .execute("UPDATE schema_version SET version = ?1", [version])
        .unwrap();
    drop(connection);
    path
}

fn canonical_v9_database(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "gocode-schema-preflight-canonical-{name}-{}-{nonce}.sqlite",
        std::process::id()
    ));
    let connection = open_with_pragmas(path.to_str().unwrap()).unwrap();
    apply_migrations(&connection).unwrap();
    drop(connection);
    path
}

fn current_database(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "gocode-schema-preflight-current-{name}-{}-{nonce}.sqlite",
        std::process::id()
    ))
}

fn snapshot(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

fn assert_unchanged(path: &Path, before: &[u8]) {
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert!(!PathBuf::from(format!("{}-wal", path.display())).exists());
    assert!(!PathBuf::from(format!("{}-shm", path.display())).exists());
    let connection = Connection::open(path).unwrap();
    let value: String = connection
        .query_row("SELECT value FROM candidate_data", [], |row| row.get(0))
        .unwrap();
    assert_eq!(value, "unchanged");
}

fn snapshot_file_set(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    ["", "-wal", "-shm"]
        .into_iter()
        .filter_map(|suffix| {
            let file = PathBuf::from(format!("{}{suffix}", path.display()));
            file.exists()
                .then(|| (file.clone(), std::fs::read(file).unwrap()))
        })
        .collect()
}

fn assert_file_set_unchanged(before: &[(PathBuf, Vec<u8>)]) {
    for (path, bytes) in before {
        assert_eq!(
            std::fs::read(path).unwrap(),
            *bytes,
            "{} changed",
            path.display()
        );
    }
}

fn assert_diagnostic<T: std::fmt::Debug>(
    result: Result<T, rusqlite::Error>,
    diagnostic: SchemaOpenDiagnostic,
) {
    let error = result.unwrap_err();
    assert_eq!(error.to_string(), diagnostic.to_string());
}

#[test]
fn shared_opener_rejects_existing_zero_byte_database_before_writable_open() {
    let path = candidate_database("zero-byte");
    std::fs::write(&path, []).unwrap();
    let before = snapshot_file_set(&path);

    assert_diagnostic(
        open_with_pragmas(path.to_str().unwrap()),
        SchemaOpenDiagnostic::ZeroByteDatabase,
    );
    assert_file_set_unchanged(&before);
}

#[test]
fn shared_opener_rejects_existing_sidecars_before_recovery_or_wal() {
    for suffix in ["-wal", "-shm"] {
        let path = candidate_database(&format!("sidecar-{}", &suffix[1..]));
        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
        std::fs::write(&sidecar, b"preserve-sidecar").unwrap();
        let before = snapshot_file_set(&path);

        assert_diagnostic(
            open_with_pragmas(path.to_str().unwrap()),
            SchemaOpenDiagnostic::SidecarPresent,
        );
        assert_file_set_unchanged(&before);
    }
}

#[test]
fn shared_opener_rejects_uri_metacharacter_path_without_mapping_another_file() {
    // Percent is an URI metacharacter and remains a valid filename on Windows.
    let path = candidate_database("uri%query");
    let before = snapshot_file_set(&path);

    assert_diagnostic(
        open_with_pragmas(path.to_str().unwrap()),
        SchemaOpenDiagnostic::UnsafePath,
    );
    assert_file_set_unchanged(&before);
}

#[cfg(unix)]
#[test]
fn shared_opener_rejects_symlink_when_file_identity_cannot_be_confirmed() {
    use std::os::unix::fs::symlink;

    let target = candidate_database("identity-target");
    let link = target.with_file_name("gocode-schema-preflight-identity-link.sqlite");
    let _ = std::fs::remove_file(&link);
    symlink(&target, &link).unwrap();
    let before = snapshot_file_set(&target);

    assert_diagnostic(
        open_with_pragmas(link.to_str().unwrap()),
        SchemaOpenDiagnostic::FileIdentityUncertain,
    );
    assert_file_set_unchanged(&before);
}

#[test]
fn store_transaction_rejects_candidate_schema_without_side_effects() {
    let path = candidate_database("store-transaction");
    let before = snapshot(&path);

    let result = StoreTransaction::open(
        path.to_str().unwrap(),
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    );

    assert!(matches!(
        result,
        Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
    ));
    assert_unchanged(&path, &before);
}

#[test]
fn migration_store_rejects_candidate_schema_without_side_effects() {
    let path = candidate_database("migration-store");
    let before = snapshot(&path);

    let result = SqliteMigrationControlStore::open(&path);

    assert!(matches!(
        result,
        Err(gocode_application::migration::ports::MigrationStoreError::Unavailable)
    ));
    assert_unchanged(&path, &before);
}

#[test]
fn atomic_pre_effect_store_rejects_candidate_schema_without_side_effects() {
    let path = candidate_database("atomic-pre-effect");
    let before = snapshot(&path);

    let result = SqliteAtomicPreEffectStore::open(&path);

    assert!(matches!(
        result,
        Err(AtomicTransactionError::StoreUnavailable)
    ));
    assert_unchanged(&path, &before);
}

#[test]
fn verification_stores_reject_candidate_schema_without_side_effects() {
    let path = candidate_database("verification-stores");
    let before = snapshot(&path);

    assert!(SqliteEvidenceStore::open(&path).is_err());
    assert_unchanged(&path, &before);
    assert!(SqliteIntentStore::open(&path).is_err());
    assert_unchanged(&path, &before);
}

#[test]
fn all_store_entry_points_reject_future_schema_versions_without_side_effects() {
    for version in [10, 11] {
        let path = candidate_database_version(&format!("all-entry-points-v{version}"), version);
        let before = snapshot(&path);

        assert!(
            StoreTransaction::open(
                path.to_str().unwrap(),
                RuntimeAuthorityId("test-host".into()),
                available_guard(),
            )
            .is_err()
        );
        assert_unchanged(&path, &before);
        assert!(SqliteMigrationControlStore::open(&path).is_err());
        assert_unchanged(&path, &before);
        assert!(SqliteAtomicPreEffectStore::open(&path).is_err());
        assert_unchanged(&path, &before);
        assert!(SqliteEvidenceStore::open(&path).is_err());
        assert_unchanged(&path, &before);
        assert!(SqliteIntentStore::open(&path).is_err());
        assert_unchanged(&path, &before);
    }
}
