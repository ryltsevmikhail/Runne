mod rejection;
mod selector_parity;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{
    QualificationFaultContext, QualificationFaultSelector, QualificationFaultVerifier,
    QualificationProcessRole,
};

const NOW: u64 = 1_800_000_000;

fn context(
    selector: QualificationFaultSelector,
    role: QualificationProcessRole,
) -> QualificationFaultContext {
    QualificationFaultContext::new(
        selector, role, [0xaa; 32], [0xbb; 32], [0xcc; 20], "run-42", [0xdd; 32],
    )
    .expect("valid context")
}

fn unsigned_ticket() -> Value {
    json!({
        "schema_version": "runne/macos-xpc-dpk-fault-ticket/v1",
        "ticket_id": "11".repeat(32),
        "selector": "kill_before_native_effect",
        "process_role": "service",
        "candidate_sha256": "aa".repeat(32),
        "release_tuple_v3_sha256": "bb".repeat(32),
        "source_revision": "cc".repeat(20),
        "workflow_run_id": "run-42",
        "namespace_sha256": "dd".repeat(32),
        "issued_at": NOW,
        "expires_at": NOW + 600,
        "nonce": URL_SAFE_NO_PAD.encode([0x22; 32]),
    })
}

fn sign(value: &Value, key: &SigningKey) -> Vec<u8> {
    let payload = crate::wire::test_signing_payload(value).expect("canonical unsigned payload");
    let signature = key.sign(&payload);
    let mut value = value.clone();
    value.as_object_mut().expect("object").insert(
        "signature".into(),
        json!({
            "algorithm": "ed25519",
            "key_id": hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
            "value": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }),
    );
    crate::wire::test_canonical_ticket(&value).expect("canonical ticket")
}

#[test]
fn valid_ticket_is_verified_once_and_yields_move_only_binding() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let bytes = sign(&unsigned_ticket(), &key);
    let mut verifier = QualificationFaultVerifier::for_test(key.verifying_key());
    let fault = verifier
        .verify_and_consume(
            &bytes,
            &context(
                QualificationFaultSelector::BeforeNativeEffect,
                QualificationProcessRole::Service,
            ),
            NOW,
        )
        .expect("valid ticket");
    assert_eq!(
        fault.selector(),
        QualificationFaultSelector::BeforeNativeEffect
    );
    assert_eq!(fault.process_role(), QualificationProcessRole::Service);
    assert_eq!(fault.ticket_id(), [0x11; 32]);
    assert_eq!(
        verifier
            .verify_and_consume(
                &bytes,
                &context(
                    QualificationFaultSelector::BeforeNativeEffect,
                    QualificationProcessRole::Service,
                ),
                NOW,
            )
            .expect_err("replay must fail"),
        crate::QualificationFaultError::Replay
    );
}

#[test]
fn nonce_cannot_be_replayed_under_a_new_ticket_identifier() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let first = sign(&unsigned_ticket(), &key);
    let mut second_value = unsigned_ticket();
    second_value["ticket_id"] = json!("33".repeat(32));
    let second = sign(&second_value, &key);
    let ctx = context(
        QualificationFaultSelector::BeforeNativeEffect,
        QualificationProcessRole::Service,
    );
    let mut verifier = QualificationFaultVerifier::for_test(key.verifying_key());
    verifier
        .verify_and_consume(&first, &ctx, NOW)
        .expect("first ticket");
    assert_eq!(
        verifier
            .verify_and_consume(&second, &ctx, NOW)
            .expect_err("nonce replay must fail"),
        crate::QualificationFaultError::Replay
    );
}

#[test]
fn compiled_policy_is_unavailable_without_build_time_key() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let bytes = sign(&unsigned_ticket(), &key);
    let error = QualificationFaultVerifier::from_compiled_policy()
        .verify_and_consume(
            &bytes,
            &context(
                QualificationFaultSelector::BeforeNativeEffect,
                QualificationProcessRole::Service,
            ),
            NOW,
        )
        .expect_err("unprovisioned builds stay inert");
    assert_eq!(error, crate::QualificationFaultError::PolicyUnavailable);
}

#[test]
fn malformed_compile_time_policy_is_unavailable() {
    assert!(crate::compiled_policy::decode_policy(Some("not+base64/"), Some("00")).is_none());
    assert!(crate::compiled_policy::decode_policy(Some("AAAA"), Some("00")).is_none());
}

#[test]
fn canonical_compile_time_policy_decodes_and_rejects_substitutions() {
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let encoded_key = URL_SAFE_NO_PAD.encode(key.as_bytes());
    let key_id = hex::encode(Sha256::digest(key.as_bytes()));
    let policy = crate::compiled_policy::decode_policy(Some(&encoded_key), Some(&key_id))
        .expect("canonical policy");
    assert_eq!(policy.key.as_bytes(), key.as_bytes());
    assert_eq!(hex::encode(policy.key_id), key_id);

    let wrong_key_id = "00".repeat(32);
    assert!(
        crate::compiled_policy::decode_policy(Some(&encoded_key), Some(&wrong_key_id)).is_none()
    );
    assert!(
        crate::compiled_policy::decode_policy(Some(&encoded_key), Some(&key_id.to_uppercase()))
            .is_none()
    );
    assert!(
        crate::compiled_policy::decode_policy(Some(&(encoded_key + "=")), Some(&key_id)).is_none()
    );
}
