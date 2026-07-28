use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gocode_application::{
    ports::{CommitError, RuntimeAuthorityId, StorageFailureKind},
    security::atomic_transaction::AtomicTransactionError,
};
use gocode_store::schema::{apply_migrations, open_with_pragmas, preflight_existing_file};
use gocode_store::{
    atomic_pre_effect::SqliteAtomicPreEffectStore,
    migration_store::SqliteMigrationControlStore,
    store::StoreTransaction,
    verification::{evidence_store::SqliteEvidenceStore, intent_store::SqliteIntentStore},
};
use rusqlite::{Connection, OpenFlags};

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
    let path = candidate_database(name);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    let connection = open_with_pragmas(path.to_str().unwrap()).unwrap();
    apply_migrations(&connection).unwrap();
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

#[test]
fn preflight_rejects_partial_v9_that_contains_legacy_required_fragments() {
    let path = candidate_database("partial-v9");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE schema_lineage (schema_version INTEGER PRIMARY KEY, provenance TEXT NOT NULL);
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

#[test]
fn preflight_rejects_existing_empty_lineage_and_fake_v8_before_wal() {
    for (name, schema) in [
        (
            "no-schema-version",
            "CREATE TABLE unrelated (value TEXT NOT NULL);",
        ),
        (
            "fake-v8",
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY);\
             INSERT INTO schema_version VALUES (8);",
        ),
        (
            "partial-v7",
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY);\
             INSERT INTO schema_version VALUES (7);",
        ),
    ] {
        let path = candidate_database(name);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("DROP TABLE schema_version;")
            .unwrap();
        connection.execute_batch(schema).unwrap();
        drop(connection);
        let before = snapshot(&path);

        assert!(preflight_existing_file(&path).is_err(), "{name}");
        assert_unchanged(&path, &before);
    }
}

#[test]
fn shared_opener_rejects_hot_wal_candidate_without_changing_any_file() {
    let path = candidate_database("hot-wal");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
    let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    reader
        .execute_batch("BEGIN; SELECT * FROM candidate_data;")
        .unwrap();
    writer
        .execute("INSERT INTO candidate_data VALUES ('hot-wal')", [])
        .unwrap();
    drop(writer);
    let before = snapshot_file_set(&path);
    assert!(
        before
            .iter()
            .any(|(file, _)| file.to_string_lossy().ends_with("-wal"))
    );

    assert!(open_with_pragmas(path.to_str().unwrap()).is_err());
    assert_file_set_unchanged(&before);
    drop(reader);
}

#[test]
fn preflight_rejects_index_semantic_changes_and_unnamed_critical_objects() {
    let index_path = canonical_v9_database("unique-index");
    let connection = Connection::open(&index_path).unwrap();
    connection
        .execute_batch(
            "DROP INDEX idx_evidence_run;
             CREATE UNIQUE INDEX idx_evidence_run ON verification_evidence(run_id);",
        )
        .unwrap();
    drop(connection);
    let before = snapshot(&index_path);
    assert!(preflight_existing_file(&index_path).is_err());
    assert_eq!(snapshot(&index_path), before);
    assert!(!PathBuf::from(format!("{}-wal", index_path.display())).exists());
    assert!(!PathBuf::from(format!("{}-shm", index_path.display())).exists());

    let trigger_path = canonical_v9_database("anonymous-trigger");
    let connection = Connection::open(&trigger_path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER audit AFTER INSERT ON verification_evidence
             BEGIN SELECT 1; END;",
        )
        .unwrap();
    drop(connection);
    let before = snapshot(&trigger_path);
    assert!(preflight_existing_file(&trigger_path).is_err());
    assert_eq!(snapshot(&trigger_path), before);
    assert!(!PathBuf::from(format!("{}-wal", trigger_path.display())).exists());
    assert!(!PathBuf::from(format!("{}-shm", trigger_path.display())).exists());
}

#[test]
fn shared_opener_admits_new_released_v8_and_canonical_v9_files() {
    let new_path = std::env::temp_dir().join("gocode-schema-preflight-new.sqlite");
    let _ = std::fs::remove_file(&new_path);
    let new_conn = open_with_pragmas(new_path.to_str().unwrap()).unwrap();
    apply_migrations(&new_conn).unwrap();
    drop(new_conn);

    let v8_path = std::env::temp_dir().join("gocode-schema-preflight-v8.sqlite");
    let _ = std::fs::remove_file(&v8_path);
    let v8_conn = Connection::open(&v8_path).unwrap();
    apply_migrations(&v8_conn).unwrap();
    v8_conn
        .execute_batch(
            "DROP TABLE schema_lineage;
             DROP TABLE consumption_intents;
             DROP TABLE verification_evidence;
             DELETE FROM schema_version WHERE version = 9;",
        )
        .unwrap();
    drop(v8_conn);
    assert!(open_with_pragmas(v8_path.to_str().unwrap()).is_ok());

    assert!(open_with_pragmas(new_path.to_str().unwrap()).is_ok());

    for path in [new_path, v8_path] {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
