use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gocode_application::{
    ports::{CommitError, RuntimeAuthorityId, StorageFailureKind},
    security::atomic_transaction::AtomicTransactionError,
};
use gocode_store::{
    atomic_pre_effect::SqliteAtomicPreEffectStore, migration_store::SqliteMigrationControlStore,
    store::StoreTransaction,
};
use gocode_store::schema::preflight_existing_file;
use rusqlite::Connection;

fn candidate_database(name: &str) -> PathBuf {
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
    drop(connection);
    path
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

#[test]
fn store_transaction_rejects_candidate_schema_without_side_effects() {
    let path = candidate_database("store-transaction");
    let before = snapshot(&path);

    let result = StoreTransaction::open(
        path.to_str().unwrap(),
        RuntimeAuthorityId("test-host".into()),
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
fn preflight_rejects_partial_v9_that_contains_legacy_required_fragments() {
    let path = candidate_database("partial-v9");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "DROP TABLE candidate_data;
             CREATE TABLE schema_lineage (schema_version INTEGER PRIMARY KEY, provenance TEXT NOT NULL);
             INSERT INTO schema_lineage VALUES (9, 'released-v8-to-strict-v9');
             CREATE TABLE verification_evidence (
                 evidence_id BLOB PRIMARY KEY CHECK(length(evidence_id) = 16),
                 layer INTEGER NOT NULL CHECK(layer IN (0, 1, 2, 3, 4, 5)),
                 verified_by TEXT NOT NULL CHECK(length(verified_by) > 0)
             );
             CREATE TABLE consumption_intents (
                 intent_id BLOB PRIMARY KEY CHECK(length(intent_id) = 16),
                 idempotency_key TEXT NOT NULL UNIQUE,
                 integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32)
             );",
        )
        .unwrap();
    drop(connection);
    let before = snapshot(&path);

    assert!(preflight_existing_file(&path).is_err());
    assert_unchanged(&path, &before);
}
