use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{NOW, sign_run_context, unsigned_run_context};
use crate::{QualificationRunContextError, QualificationRunContextVerifier};

fn signed_base() -> (SigningKey, [u8; 32], Vec<u8>) {
    let key = SigningKey::from_bytes(&[9; 32]);
    let ticket_sha256 = [0x55; 32];
    let bytes = sign_run_context(&unsigned_run_context(ticket_sha256), &key);
    (key, ticket_sha256, bytes)
}

fn verify(value: &Value) -> Result<(), QualificationRunContextError> {
    let key = SigningKey::from_bytes(&[9; 32]);
    let digest = [0x55; 32];
    QualificationRunContextVerifier::for_test(key.verifying_key())
        .verify_and_consume(
            &sign_run_context(value, &key),
            &super::run_context_expectation(digest),
            NOW,
        )
        .map(|_| ())
}

#[test]
fn runner_context_rejects_noncanonical_duplicate_and_unknown_json() {
    let (key, digest, bytes) = signed_base();
    let source = String::from_utf8(bytes).expect("UTF-8 context");
    let duplicate = source.replacen(
        '{',
        "{\"schema_version\":\"runne/macos-xpc-dpk-run-context/v1\",",
        1,
    );
    let spaced = source.replacen('{', "{ ", 1);
    let mut unknown: Value = serde_json::from_str(&source).expect("context JSON");
    unknown["extra"] = json!(true);
    for bytes in [
        duplicate.into_bytes(),
        spaced.into_bytes(),
        serde_json::to_vec(&unknown).expect("JSON"),
    ] {
        assert_eq!(
            QualificationRunContextVerifier::for_test(key.verifying_key())
                .verify_and_consume(&bytes, &super::run_context_expectation(digest), NOW)
                .err()
                .expect("closed JSON must reject mutation"),
            QualificationRunContextError::InvalidContext
        );
    }
    assert_eq!(
        QualificationRunContextVerifier::for_test(key.verifying_key())
            .verify_and_consume(
                &vec![b'x'; crate::MAX_RUN_CONTEXT_BYTES + 1],
                &super::run_context_expectation(digest),
                NOW,
            )
            .err(),
        Some(QualificationRunContextError::InvalidContext)
    );
}

#[test]
fn runner_context_rejects_every_noncanonical_field_shape_and_role_pair() {
    let cases = [
        ("schema_version", json!("wrong/v1")),
        ("context_id", json!("33")),
        ("scenario_id", json!("other")),
        ("selector", json!("kill_arbitrary_process")),
        ("process_role", json!("runtime")),
        ("candidate_sha256", json!("AA".repeat(32))),
        ("release_tuple_v3_sha256", json!("bb")),
        ("source_revision", json!("cc")),
        ("workflow_run_id", json!("bad/run")),
        ("namespace_sha256", json!("dd")),
        ("ticket_sha256", json!("55")),
        ("nonce", json!("AAAA=")),
    ];
    for (field, replacement) in cases {
        let mut value = unsigned_run_context([0x55; 32]);
        value[field] = replacement;
        assert_eq!(
            verify(&value),
            Err(QualificationRunContextError::InvalidContext),
            "{field}"
        );
    }

    let key = SigningKey::from_bytes(&[9; 32]);
    let signed = sign_run_context(&unsigned_run_context([0x55; 32]), &key);
    let signed: Value = serde_json::from_slice(&signed).expect("context");
    for (field, replacement) in [
        ("algorithm", json!("rsa")),
        ("key_id", json!("ee")),
        ("value", json!("not+base64/")),
    ] {
        let mut value = signed.clone();
        value["signature"][field] = replacement;
        let bytes = crate::context_wire::test_canonical_context(&value).expect("wire context");
        assert_eq!(
            QualificationRunContextVerifier::for_test(key.verifying_key())
                .verify_and_consume(&bytes, &super::run_context_expectation([0x55; 32]), NOW,)
                .err(),
            Some(QualificationRunContextError::InvalidContext),
            "signature.{field}"
        );
    }
}

#[test]
fn runner_context_rejects_wrong_key_domain_and_forged_signature() {
    let trusted = SigningKey::from_bytes(&[9; 32]);
    let attacker = SigningKey::from_bytes(&[10; 32]);
    let digest = [0x55; 32];
    let expected = super::run_context_expectation(digest);
    let forged = sign_run_context(&unsigned_run_context(digest), &attacker);
    assert_eq!(
        QualificationRunContextVerifier::for_test(trusted.verifying_key())
            .verify_and_consume(&forged, &expected, NOW)
            .err()
            .expect("foreign key must fail"),
        QualificationRunContextError::InvalidSignature
    );
    let mut forged: Value = serde_json::from_slice(&forged).expect("forged context");
    forged["signature"]["key_id"] = json!(hex::encode(Sha256::digest(
        trusted.verifying_key().as_bytes()
    )));
    let forged = crate::context_wire::test_canonical_context(&forged).expect("forged wire");
    assert_eq!(
        QualificationRunContextVerifier::for_test(trusted.verifying_key())
            .verify_and_consume(&forged, &expected, NOW)
            .err(),
        Some(QualificationRunContextError::InvalidSignature)
    );

    let value = unsigned_run_context(digest);
    let payload = crate::context_wire::test_signing_payload(&value).expect("payload");
    let signature = trusted.sign(&payload[crate::context_wire::SIGNATURE_DOMAIN.len()..]);
    let mut undomained = value;
    undomained["signature"] = json!({
        "algorithm": "ed25519",
        "key_id": hex::encode(Sha256::digest(trusted.verifying_key().as_bytes())),
        "value": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    });
    let bytes = crate::context_wire::test_canonical_context(&undomained).expect("context");
    assert_eq!(
        QualificationRunContextVerifier::for_test(trusted.verifying_key())
            .verify_and_consume(&bytes, &expected, NOW)
            .err()
            .expect("missing domain must fail"),
        QualificationRunContextError::InvalidSignature
    );
}

#[test]
fn runner_context_rejects_expected_field_substitution() {
    let key = SigningKey::from_bytes(&[9; 32]);
    let digest = [0x55; 32];
    for field in [
        "scenario_id",
        "selector",
        "process_role",
        "candidate_sha256",
        "release_tuple_v3_sha256",
        "source_revision",
        "workflow_run_id",
        "namespace_sha256",
        "ticket_sha256",
    ] {
        let mut value = unsigned_run_context(digest);
        value[field] = match field {
            "scenario_id" => json!("other"),
            "selector" => json!("kill_after_native_effect"),
            "process_role" => json!("runtime"),
            "source_revision" => json!("00".repeat(20)),
            "workflow_run_id" => json!("run-43"),
            _ => json!("00".repeat(32)),
        };
        let bytes = sign_run_context(&value, &key);
        let error = QualificationRunContextVerifier::for_test(key.verifying_key())
            .verify_and_consume(&bytes, &super::run_context_expectation(digest), NOW)
            .err()
            .expect("expected binding substitution must fail");
        assert!(
            matches!(
                error,
                QualificationRunContextError::InvalidContext
                    | QualificationRunContextError::BindingMismatch
            ),
            "{field}: {error:?}"
        );
    }
}

#[test]
fn runner_context_rejects_stale_future_zero_and_overlong_lifetimes() {
    for (issued, expires) in [
        (NOW - 901, NOW - 1),
        (NOW + 1, NOW + 10),
        (NOW, NOW),
        (NOW, NOW + 901),
    ] {
        let mut value = unsigned_run_context([0x55; 32]);
        value["issued_at"] = json!(issued);
        value["expires_at"] = json!(expires);
        assert_eq!(
            verify(&value),
            Err(QualificationRunContextError::InvalidTime)
        );
    }
    let mut unsafe_time = unsigned_run_context([0x55; 32]);
    unsafe_time["expires_at"] = json!(9_007_199_254_740_992_u64);
    assert_eq!(
        verify(&unsafe_time),
        Err(QualificationRunContextError::InvalidTime)
    );
}

#[test]
fn runner_context_expectation_rejects_role_and_workflow_ambiguity() {
    for (role, workflow) in [
        (crate::QualificationProcessRole::Runtime, "run-42"),
        (crate::QualificationProcessRole::Service, "bad/run"),
    ] {
        assert!(
            crate::QualificationRunContextExpectation::new(
                crate::QualificationScenario::MacosXpcDpkV1,
                crate::QualificationFaultSelector::BeforeNativeEffect,
                role,
                [0xaa; 32],
                [0xbb; 32],
                [0xcc; 20],
                workflow,
                [0xdd; 32],
                [0x55; 32],
            )
            .is_err()
        );
    }
}

#[test]
fn malformed_context_compile_time_policy_is_unavailable() {
    assert!(crate::context_policy::decode_policy(Some("not+base64/"), Some("00")).is_none());
    let key = SigningKey::from_bytes(&[9; 32]).verifying_key();
    let encoded = URL_SAFE_NO_PAD.encode(key.as_bytes());
    let key_id = hex::encode(Sha256::digest(key.as_bytes()));
    assert!(
        crate::context_policy::decode_policy(Some(&(encoded.clone() + "=")), Some(&key_id))
            .is_none()
    );
    assert!(crate::context_policy::decode_policy(Some(&encoded), Some(&"00".repeat(32))).is_none());
}
