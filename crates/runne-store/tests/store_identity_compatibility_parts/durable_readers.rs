#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use runne_application::verification::evidence_recorder::EvidenceRecorder;
use runne_domain::verification::digest::VerificationDigest;
use runne_domain::verification::identity::IntentID;
use runne_store::provider::SqliteProviderRecoveryStore;
use runne_store::verification::evidence_store::SqliteEvidenceStore;
use runne_store::verification::intent_store::SqliteIntentStore;
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::vectors::{EVIDENCE_DIGEST, INTENT_DIGEST, file_snapshot, sidecar_path};

#[test]
fn source_pinned_intent_row_reopens_without_mutation_and_runne_alias_rejects() {
    let root = tempfile::tempdir().unwrap();
    let canonical = root.path().join("canonical.sqlite");
    let store = SqliteIntentStore::open(&canonical).unwrap();
    seed_intent(&canonical, INTENT_DIGEST);
    let before = file_snapshot(&canonical);
    let intent = IntentID::from_bytes([1; 16]);
    let reopened = store
        .reserve(
            intent,
            "sourcecraft-intent",
            VerificationDigest::from_bytes([2; 32]),
            VerificationDigest::from_bytes([3; 32]),
        )
        .unwrap();
    assert_eq!(reopened.integrity_digest.as_bytes(), &INTENT_DIGEST);
    assert_eq!(file_snapshot(&canonical), before);

    let alias = root.path().join("runne-alias.sqlite");
    let store = SqliteIntentStore::open(&alias).unwrap();
    let mut runne_digest = INTENT_DIGEST;
    runne_digest[0] ^= 0x80;
    seed_intent(&alias, runne_digest);
    let before = file_snapshot(&alias);
    assert!(
        store
            .reserve(
                intent,
                "sourcecraft-intent",
                VerificationDigest::from_bytes([2; 32]),
                VerificationDigest::from_bytes([3; 32]),
            )
            .is_err()
    );
    assert_eq!(file_snapshot(&alias), before);
}

#[tokio::test]
async fn source_pinned_evidence_row_is_read_without_current_writer() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("evidence.sqlite");
    let store = SqliteEvidenceStore::open(&path).unwrap();
    let run = Uuid::from_bytes([7; 16]);
    let evidence = Uuid::from_bytes([8; 16]);
    Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO verification_evidence (evidence_id, run_id, profile_id, profile_digest, layer, evidence_type, evidence_digest, content_ref, source, producer_identity, sensitivity, verified_by) VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, 'sourcecraft:556f', 'sourcecraft', 'compatibility-vector', 0, 'reader')",
            params![evidence.as_bytes(), run.as_bytes(), [9_u8; 16].as_slice(), [10_u8; 32].as_slice(), EVIDENCE_DIGEST.as_slice()],
        )
        .unwrap();
    let before = file_snapshot(&path);
    assert_eq!(store.list_for_run(&run).await.unwrap(), vec![evidence]);
    assert_eq!(file_snapshot(&path), before);
}

#[test]
fn source_pinned_scanner_sidecar_reopens_and_runne_schema_alias_is_unchanged() {
    let root = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let daemon = root.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    let base = daemon.join("event-log.sqlite");
    let canonical = sidecar_path(&base);
    seed_sidecar(&canonical, "gocode.provider-scanner-recovery");
    let before = file_snapshot(&canonical);
    drop(SqliteProviderRecoveryStore::open(&base, [0x41; 16]).unwrap());
    assert_eq!(file_snapshot(&canonical), before);

    let alias_base = daemon.join("runne-alias.sqlite");
    let alias = sidecar_path(&alias_base);
    seed_sidecar(&alias, "runne.provider-scanner-recovery");
    let before = file_snapshot(&alias);
    assert!(SqliteProviderRecoveryStore::open(&alias_base, [0x41; 16]).is_err());
    assert_eq!(file_snapshot(&alias), before);
}

fn seed_intent(path: &Path, digest: [u8; 32]) {
    Connection::open(path)
        .unwrap()
        .execute(
            "INSERT INTO consumption_intents (intent_id, idempotency_key, state, gate_head_snapshot_digest, target_artifact_digest, integrity_digest) VALUES (?1, 'sourcecraft-intent', 'Reserved', ?2, ?3, ?4)",
            params![[1_u8; 16].as_slice(), [2_u8; 32].as_slice(), [3_u8; 32].as_slice(), digest.as_slice()],
        )
        .unwrap();
}

fn seed_sidecar(path: &Path, kind: &str) {
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    let identity = format!(
        "CREATE TABLE scanner_recovery_schema (id INTEGER PRIMARY KEY CHECK(id = 1), schema_kind TEXT NOT NULL CHECK(schema_kind = '{kind}'), schema_version INTEGER NOT NULL CHECK(schema_version = 2), authority_id BLOB NOT NULL CHECK(length(authority_id) = 16))"
    );
    connection.execute_batch(&identity).unwrap();
    connection.execute_batch("CREATE TABLE provider_scanner_recovery (attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id) = 16), fencing_token INTEGER NOT NULL CHECK(fencing_token > 0), policy_epoch INTEGER NOT NULL CHECK(policy_epoch > 0), matcher_epoch INTEGER NOT NULL CHECK(matcher_epoch > 0), algorithm_version INTEGER NOT NULL CHECK(algorithm_version > 0), tail_id BLOB CHECK(tail_id IS NULL OR length(tail_id) = 16), tail_version INTEGER CHECK(tail_version IS NULL OR tail_version > 0), binding_digest BLOB CHECK(binding_digest IS NULL OR length(binding_digest) = 32), checkpoint_sequence INTEGER CHECK(checkpoint_sequence IS NULL OR checkpoint_sequence > 0), checkpoint_cursor INTEGER CHECK(checkpoint_cursor IS NULL OR checkpoint_cursor >= 0), checkpoint_safe_high_water INTEGER CHECK(checkpoint_safe_high_water IS NULL OR checkpoint_safe_high_water >= 0), checkpoint_id BLOB CHECK(checkpoint_id IS NULL OR length(checkpoint_id) = 16), checkpoint_digest BLOB CHECK(checkpoint_digest IS NULL OR length(checkpoint_digest) = 32), durable_cursor INTEGER NOT NULL DEFAULT 0 CHECK(durable_cursor >= 0), durable_safe_high_water INTEGER NOT NULL DEFAULT 0 CHECK(durable_safe_high_water >= 0), durable_checkpoint_digest BLOB CHECK(durable_checkpoint_digest IS NULL OR length(durable_checkpoint_digest) = 32), completion_checkpoint_digest BLOB CHECK(completion_checkpoint_digest IS NULL OR length(completion_checkpoint_digest) = 32), disposition INTEGER CHECK(disposition IS NULL OR disposition BETWEEN 1 AND 6), CHECK(completion_checkpoint_digest IS NULL OR completion_checkpoint_digest = durable_checkpoint_digest), CHECK((tail_id IS NULL AND tail_version IS NULL AND binding_digest IS NULL AND checkpoint_sequence IS NULL AND checkpoint_cursor IS NULL AND checkpoint_safe_high_water IS NULL AND checkpoint_id IS NULL AND checkpoint_digest IS NULL) OR (tail_id IS NOT NULL AND tail_version IS NOT NULL AND binding_digest IS NOT NULL AND checkpoint_sequence IS NOT NULL AND checkpoint_cursor IS NOT NULL AND checkpoint_safe_high_water IS NOT NULL AND checkpoint_id IS NOT NULL AND checkpoint_digest IS NOT NULL)))").unwrap();
    connection
        .pragma_update(None, "user_version", 2_i64)
        .unwrap();
    connection.execute("INSERT INTO scanner_recovery_schema (id, schema_kind, schema_version, authority_id) VALUES (1, ?1, 2, ?2)", params![kind, [0x41_u8; 16].as_slice()]).unwrap();
    drop(connection);
    #[cfg(unix)]
    for file in [
        path.to_path_buf(),
        std::path::PathBuf::from(format!("{}-wal", path.display())),
        std::path::PathBuf::from(format!("{}-shm", path.display())),
    ] {
        if file.exists() {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}
