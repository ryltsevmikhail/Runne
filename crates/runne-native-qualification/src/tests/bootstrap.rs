use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{
    PendingQualificationRunBootstrapProof, QualificationRunBootstrapError,
    QualificationRunBootstrapExpectation, QualificationRunBootstrapVerifier,
};

const NOW: u64 = 1_800_000_000;

fn unsigned() -> Value {
    json!({
        "schema_version": "runne/macos-xpc-dpk-run-bootstrap/v1",
        "context_id": "11".repeat(32),
        "challenge": "33".repeat(32),
        "candidate_sha256": "aa".repeat(32),
        "raw_v3_tuple_sha256": "bb".repeat(32),
        "source_revision": "cc".repeat(20),
        "workflow_run_id": "run-42",
        "namespace_sha256": "dd".repeat(32),
        "manifest_sha256": "ee".repeat(32),
        "profile_sha256": "ff".repeat(32),
        "issued_at": NOW,
        "expires_at": NOW + 300,
        "run_not_after": NOW + 3600,
        "nonce": URL_SAFE_NO_PAD.encode([0x22; 32]),
    })
}

fn sign(value: &Value, key: &SigningKey) -> Vec<u8> {
    let payload = crate::bootstrap_wire::test_signing_payload(value).expect("payload");
    let signature = key.sign(&payload);
    let mut signed = value.clone();
    signed.as_object_mut().expect("object").insert(
        "signature".into(),
        json!({
            "algorithm": "ed25519",
            "key_id": hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
            "value": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }),
    );
    crate::bootstrap_wire::test_canonical(&signed).expect("canonical proof")
}

fn expected() -> QualificationRunBootstrapExpectation {
    expected_with([0x11; 32], [0x22; 32])
}

fn expected_with(context_id: [u8; 32], nonce: [u8; 32]) -> QualificationRunBootstrapExpectation {
    QualificationRunBootstrapExpectation::new(
        [0xaa; 32],
        [0xbb; 32],
        [0xcc; 20],
        "run-42",
        [0xdd; 32],
        [0xee; 32],
        [0xff; 32],
        context_id,
        nonce,
        [0x33; 32],
        NOW,
        NOW + 300,
        NOW + 3600,
        3600,
    )
    .expect("expectation")
}

fn verify(value: &Value) -> Result<(), QualificationRunBootstrapError> {
    let key = SigningKey::from_bytes(&[9; 32]);
    let pending = PendingQualificationRunBootstrapProof::from_signed_bytes(sign(value, &key))
        .expect("canonical pending proof");
    QualificationRunBootstrapVerifier::test_only_from_verifying_key(key.verifying_key())
        .verify_and_consume(pending, &expected(), NOW)
        .map(|_| ())
}

#[test]
fn bootstrap_proof_binds_exact_run_and_is_move_only() {
    let key = SigningKey::from_bytes(&[9; 32]);
    let proof = sign(&unsigned(), &key);
    let pending =
        PendingQualificationRunBootstrapProof::from_signed_bytes(proof.clone()).expect("pending");
    let mut verifier =
        QualificationRunBootstrapVerifier::test_only_from_verifying_key(key.verifying_key());
    let facts = verifier
        .verify_and_consume(pending, &expected(), NOW)
        .expect("verified");
    assert_eq!(facts.candidate_sha256(), [0xaa; 32]);
    assert_eq!(facts.raw_v3_tuple_sha256(), [0xbb; 32]);
    assert_eq!(facts.source_revision(), [0xcc; 20]);
    assert_eq!(facts.workflow_run_id(), "run-42");
    assert_eq!(facts.namespace_sha256(), [0xdd; 32]);
    assert_eq!(facts.manifest_sha256(), [0xee; 32]);
    assert_eq!(facts.profile_sha256(), [0xff; 32]);
    assert_eq!(facts.context_id(), [0x11; 32]);
    assert_eq!(facts.nonce(), [0x22; 32]);
    assert_eq!(facts.challenge(), [0x33; 32]);
    assert_eq!(facts.run_not_after(), NOW + 3600);
    assert_ne!(facts.fingerprint(), [0; 32]);
    let duplicate =
        PendingQualificationRunBootstrapProof::from_signed_bytes(proof).expect("pending");
    assert_eq!(
        verifier
            .verify_and_consume(duplicate, &expected(), NOW)
            .err(),
        Some(QualificationRunBootstrapError::Replay)
    );
}

#[test]
fn bootstrap_context_id_and_nonce_are_independent_replay_keys() {
    let key = SigningKey::from_bytes(&[9; 32]);
    let first = PendingQualificationRunBootstrapProof::from_signed_bytes(sign(&unsigned(), &key))
        .expect("first proof");
    let mut verifier =
        QualificationRunBootstrapVerifier::test_only_from_verifying_key(key.verifying_key());
    verifier
        .verify_and_consume(first, &expected(), NOW)
        .expect("first proof");
    for (field, replacement, context_id, nonce) in [
        ("context_id", json!("44".repeat(32)), [0x44; 32], [0x22; 32]),
        (
            "nonce",
            json!(URL_SAFE_NO_PAD.encode([0x55; 32])),
            [0x11; 32],
            [0x55; 32],
        ),
    ] {
        let mut value = unsigned();
        value[field] = replacement;
        let pending = PendingQualificationRunBootstrapProof::from_signed_bytes(sign(&value, &key))
            .expect("second proof");
        assert_eq!(
            verifier
                .verify_and_consume(pending, &expected_with(context_id, nonce), NOW)
                .err(),
            Some(QualificationRunBootstrapError::Replay),
            "reused {field} is rejected independently"
        );
    }
}

#[test]
fn bootstrap_proof_rejects_every_exact_binding_substitution() {
    for field in [
        "candidate_sha256",
        "raw_v3_tuple_sha256",
        "source_revision",
        "workflow_run_id",
        "namespace_sha256",
        "manifest_sha256",
        "profile_sha256",
        "context_id",
        "challenge",
        "nonce",
        "issued_at",
        "expires_at",
        "run_not_after",
    ] {
        let mut value = unsigned();
        value[field] = match field {
            "workflow_run_id" => json!("run-43"),
            "source_revision" => json!("44".repeat(20)),
            "nonce" => json!(URL_SAFE_NO_PAD.encode([0x33; 32])),
            "issued_at" => json!(NOW - 1),
            "expires_at" => json!(NOW + 299),
            "run_not_after" => json!(NOW + 3599),
            _ => json!("44".repeat(32)),
        };
        assert_eq!(
            verify(&value),
            Err(QualificationRunBootstrapError::BindingMismatch),
            "{field}"
        );
    }
}

#[test]
fn bootstrap_proof_has_distinct_signature_domain_and_closed_json() {
    let key = SigningKey::from_bytes(&[9; 32]);
    let value = unsigned();
    let payload = crate::bootstrap_wire::test_signing_payload(&value).expect("bootstrap payload");
    let canonical = &payload[crate::bootstrap_wire::SIGNATURE_DOMAIN.len()..];
    let mut context_payload = crate::context_wire::SIGNATURE_DOMAIN.to_vec();
    context_payload.extend_from_slice(canonical);
    let signature = key.sign(&context_payload);
    let mut foreign = value;
    foreign.as_object_mut().expect("object").insert("signature".into(), json!({
        "algorithm":"ed25519", "key_id":hex::encode(Sha256::digest(key.verifying_key().as_bytes())), "value":URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    }));
    let foreign = crate::bootstrap_wire::test_canonical(&foreign).expect("canonical proof");
    let pending =
        PendingQualificationRunBootstrapProof::from_signed_bytes(foreign).expect("pending");
    assert_eq!(
        QualificationRunBootstrapVerifier::test_only_from_verifying_key(key.verifying_key())
            .verify_and_consume(pending, &expected(), NOW)
            .err(),
        Some(QualificationRunBootstrapError::InvalidSignature)
    );

    let mut unknown = unsigned();
    unknown["extra"] = json!(true);
    assert!(
        PendingQualificationRunBootstrapProof::from_signed_bytes(
            serde_json::to_vec(&unknown).expect("json")
        )
        .is_err()
    );
}

#[test]
fn bootstrap_proof_rejects_zero_and_invalid_admission_windows() {
    for (field, value) in [
        ("candidate_sha256", json!("00".repeat(32))),
        ("raw_v3_tuple_sha256", json!("00".repeat(32))),
        ("source_revision", json!("00".repeat(20))),
        ("namespace_sha256", json!("00".repeat(32))),
        ("manifest_sha256", json!("00".repeat(32))),
        ("profile_sha256", json!("00".repeat(32))),
        ("context_id", json!("00".repeat(32))),
        ("challenge", json!("00".repeat(32))),
        ("nonce", json!(URL_SAFE_NO_PAD.encode([0; 32]))),
    ] {
        let mut proof = unsigned();
        proof[field] = value;
        assert_eq!(
            verify(&proof),
            Err(QualificationRunBootstrapError::InvalidProof),
            "{field}"
        );
    }
    for (issued, expires) in [
        (NOW, NOW),
        (NOW, NOW + 901),
        (NOW + 1, NOW + 2),
        (NOW - 901, NOW - 1),
    ] {
        let mut proof = unsigned();
        proof["issued_at"] = json!(issued);
        proof["expires_at"] = json!(expires);
        assert_eq!(
            verify(&proof),
            Err(QualificationRunBootstrapError::InvalidTime)
        );
    }
}

#[test]
fn bootstrap_expectation_and_unprovisioned_authority_fail_closed() {
    assert!(
        QualificationRunBootstrapExpectation::new(
            [0; 32],
            [0xbb; 32],
            [0xcc; 20],
            "run-42",
            [0xdd; 32],
            [0xee; 32],
            [0xff; 32],
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            NOW,
            NOW + 300,
            NOW + 3600,
            3600,
        )
        .is_err()
    );
    let key = SigningKey::from_bytes(&[9; 32]);
    let pending = PendingQualificationRunBootstrapProof::from_signed_bytes(sign(&unsigned(), &key))
        .expect("pending");
    assert_eq!(
        QualificationRunBootstrapVerifier::from_compiled_policy()
            .verify_and_consume(pending, &expected(), NOW)
            .err(),
        Some(QualificationRunBootstrapError::PolicyUnavailable)
    );
}
