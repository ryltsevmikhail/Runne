use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gocode_application::{
    ports::{CommitError, RuntimeAuthorityId, StorageFailureKind},
    security::atomic_transaction::AtomicTransactionError,
};
use gocode_store::schema::{apply_migrations, preflight_existing_file};
use gocode_store::{
    atomic_pre_effect::SqliteAtomicPreEffectStore,
    migration_store::SqliteMigrationControlStore,
    store::StoreTransaction,
    verification::{evidence_store::SqliteEvidenceStore, intent_store::SqliteIntentStore},
};
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

fn current_database(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "gocode-schema-preflight-{name}-{}-{nonce}.sqlite",
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
fn preflight_rejects_v11_authority_table_with_same_columns_and_missing_constraints() {
    let path = current_database("v11-authority-constraints");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("CREATE TABLE candidate_data (value TEXT NOT NULL); INSERT INTO candidate_data VALUES ('unchanged');")
        .unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch(
            "DROP TABLE provider_effect_authorities;
             CREATE TABLE provider_effect_authorities (
                 authority_id BLOB NOT NULL,
                 revision INTEGER NOT NULL,
                 attempt_id BLOB NOT NULL,
                 permit_id BLOB NOT NULL,
                 capability_grant_id TEXT NOT NULL,
                 token_reservation_id BLOB NOT NULL,
                 cost_reservation_id BLOB NOT NULL,
                 prepared_digest BLOB NOT NULL,
                 render_digest BLOB NOT NULL,
                 profile_digest BLOB NOT NULL,
                 owner_id TEXT NOT NULL,
                 scope TEXT NOT NULL,
                 fencing_token INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL,
                 revoked INTEGER NOT NULL,
                 consumed INTEGER NOT NULL,
                 consumed_intent_id TEXT,
                 PRIMARY KEY(authority_id, revision)
                 /* authority_idblobnotnullcheck(length(authority_id)=16andauthority_id!=zeroblob(16)) revisioninteger not null check(revision>0) attempt_idblobnotnullcheck(length(attempt_id)=16) permit_idblobnotnullcheck(length(permit_id)=16) capability_grant_idtextnotnullcheck(length(capability_grant_id)between1and256) token_reservation_idblobnotnullcheck(length(token_reservation_id)=16) cost_reservation_idblobnotnullcheck(length(cost_reservation_id)=16) prepared_digestblobnotnullcheck(length(prepared_digest)=32) render_digestblobnotnullcheck(length(render_digest)=32) profile_digestblobnotnullcheck(length(profile_digest)=32) owner_idtextnotnullcheck(length(owner_id)between1and256) scopetextnotnullcheck(length(scope)between1and256) fencing_tokeninteger not null check(fencing_token>0) revokedinteger not null check(revoked in (0,1)) consumedinteger not null check(consumed in (0,1)) consumed_intent_idtextunique primarykey(authority_id,revision) check((consumed=0andconsumed_intent_idisnull)or(consumed=1andconsumed_intent_idisnotnull)) */
             );",
        )
        .unwrap();
    drop(connection);
    let before = snapshot(&path);

    assert!(preflight_existing_file(&path).is_err());
    assert_unchanged(&path, &before);
}
