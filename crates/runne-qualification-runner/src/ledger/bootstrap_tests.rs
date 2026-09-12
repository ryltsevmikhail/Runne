use std::os::unix::fs::PermissionsExt as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use runne_api::RunBinding;
use runne_native_qualification::{
    PendingQualificationRunBootstrapProof, QualificationRunBootstrapExpectation,
    QualificationRunBootstrapVerifier, VerifiedQualificationRunBootstrapProof,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::super::QualificationReplayLedger;
use crate::BootstrapPreparation;

fn root() -> tempfile::TempDir {
    let root =
        tempfile::TempDir::new_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn open(root: &tempfile::TempDir) -> QualificationReplayLedger {
    QualificationReplayLedger::open_for_test(root.path(), rustix::process::geteuid().as_raw())
        .unwrap()
}

fn preparation(ids: [u8; 3], issued_at: u64) -> BootstrapPreparation {
    BootstrapPreparation::new(
        RunBinding::new(
            "run-42", [0xcc; 20], [0xaa; 32], [0xbb; 32], [0xdd; 32], [5; 32], [6; 32],
        )
        .unwrap(),
        [ids[0]; 32],
        [ids[1]; 32],
        [ids[2]; 32],
        issued_at,
        issued_at + 300,
        issued_at + 3_600,
        3_600,
    )
    .unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Clone, Serialize)]
struct Proof {
    schema_version: &'static str,
    context_id: String,
    challenge: String,
    candidate_sha256: String,
    raw_v3_tuple_sha256: String,
    source_revision: String,
    workflow_run_id: &'static str,
    namespace_sha256: String,
    manifest_sha256: String,
    profile_sha256: String,
    issued_at: u64,
    expires_at: u64,
    run_not_after: u64,
    nonce: String,
}

#[derive(Serialize)]
struct Signature {
    algorithm: &'static str,
    key_id: String,
    value: String,
}

#[derive(Serialize)]
struct Signed<T> {
    #[serde(flatten)]
    value: T,
    signature: Signature,
}

fn proof(ids: [u8; 2], issued_at: u64) -> VerifiedQualificationRunBootstrapProof {
    let key = SigningKey::from_bytes(&[0x22; 32]);
    let proof = Proof {
        schema_version: "runne/macos-xpc-dpk-run-bootstrap/v1",
        context_id: hex::encode([ids[0]; 32]),
        challenge: hex::encode([0xee; 32]),
        candidate_sha256: hex::encode([0xaa; 32]),
        raw_v3_tuple_sha256: hex::encode([0xbb; 32]),
        source_revision: hex::encode([0xcc; 20]),
        workflow_run_id: "run-42",
        namespace_sha256: hex::encode([0xdd; 32]),
        manifest_sha256: hex::encode([5; 32]),
        profile_sha256: hex::encode([6; 32]),
        issued_at,
        expires_at: issued_at + 300,
        run_not_after: issued_at + 3_600,
        nonce: URL_SAFE_NO_PAD.encode([ids[1]; 32]),
    };
    let unsigned = serde_json::to_vec(&proof).unwrap();
    let mut payload = b"runne/macos-xpc-dpk-run-bootstrap/v1\0".to_vec();
    payload.extend_from_slice(&unsigned);
    let signature = key.sign(&payload);
    let bytes = serde_json::to_vec(&Signed {
        value: proof,
        signature: Signature {
            algorithm: "ed25519",
            key_id: hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })
    .unwrap();
    let expected = QualificationRunBootstrapExpectation::new(
        [0xaa; 32],
        [0xbb; 32],
        [0xcc; 20],
        "run-42",
        [0xdd; 32],
        [5; 32],
        [6; 32],
        [ids[0]; 32],
        [ids[1]; 32],
        [0xee; 32],
        issued_at,
        issued_at + 300,
        issued_at + 3_600,
        3_600,
    )
    .unwrap();
    QualificationRunBootstrapVerifier::test_only_from_verifying_key(key.verifying_key())
        .verify_and_consume(
            PendingQualificationRunBootstrapProof::from_signed_bytes(bytes).unwrap(),
            &expected,
            issued_at,
        )
        .unwrap()
}

#[test]
fn bootstrap_state_is_durable_and_one_way() {
    let root = root();
    let issued_at = now();
    let mut ledger = open(&root);
    ledger
        .prepare_bootstrap(preparation([1, 2, 3], issued_at))
        .unwrap();
    let armed = ledger.arm_bootstrap([1; 32], [0xee; 32]).unwrap();
    assert_eq!(armed.context_id(), [2; 32]);
    assert_eq!(armed.nonce(), [3; 32]);
    assert_eq!(armed.binding().candidate_sha256(), [0xaa; 32]);
    ledger.mark_bootstrap_issued([1; 32], [9; 32]).unwrap();
    assert_eq!(
        ledger
            .load_bootstrap_issued([1; 32], [0xee; 32], [9; 32])
            .unwrap()
            .offer_id(),
        [1; 32]
    );
    ledger.consume_run(proof([2, 3], issued_at)).unwrap();
    ledger
        .mark_bootstrap_consumed([1; 32], [0xee; 32], [9; 32])
        .unwrap();
    drop(ledger);
    let mut reopened = open(&root);
    assert!(
        reopened
            .prepare_bootstrap(preparation([4, 5, 6], issued_at))
            .is_err()
    );
    assert!(reopened.arm_bootstrap([1; 32], [0xee; 32]).is_err());
}

#[test]
fn bootstrap_rejects_mismatch_duplicate_and_unsealed_consumption() {
    let issued_at = now();
    let duplicate_root = root();
    let mut ledger = open(&duplicate_root);
    ledger
        .prepare_bootstrap(preparation([1, 2, 3], issued_at))
        .unwrap();
    assert!(
        ledger
            .prepare_bootstrap(preparation([4, 5, 6], issued_at))
            .is_err()
    );

    let mismatch_root = root();
    let mut ledger = open(&mismatch_root);
    ledger
        .prepare_bootstrap(preparation([1, 2, 3], issued_at))
        .unwrap();
    ledger.arm_bootstrap([1; 32], [0xee; 32]).unwrap();
    ledger.mark_bootstrap_issued([1; 32], [9; 32]).unwrap();
    assert!(
        ledger
            .load_bootstrap_issued([1; 32], [8; 32], [9; 32])
            .is_err()
    );

    let unsealed_root = root();
    let mut ledger = open(&unsealed_root);
    ledger
        .prepare_bootstrap(preparation([1, 2, 3], issued_at))
        .unwrap();
    ledger.arm_bootstrap([1; 32], [0xee; 32]).unwrap();
    ledger.mark_bootstrap_issued([1; 32], [9; 32]).unwrap();
    assert!(
        ledger
            .mark_bootstrap_consumed([1; 32], [0xee; 32], [9; 32])
            .is_err()
    );
}

#[test]
fn v2_migration_preserves_existing_replay() {
    let root = root();
    let issued_at = now();
    let mut ledger = open(&root);
    ledger.consume_run(proof([1, 2], issued_at)).unwrap();
    drop(ledger);
    let path = root.path().join(crate::path_guard::DATABASE_NAME);
    rusqlite::Connection::open(&path).unwrap().execute_batch("BEGIN IMMEDIATE; DROP TABLE bootstrap_arms; UPDATE ledger_meta SET schema_id='runne/qualification-runner-replay/v2'; PRAGMA user_version=2; COMMIT;").unwrap();
    let mut upgraded = open(&root);
    assert!(upgraded.consume_run(proof([1, 2], issued_at)).is_err());
}
