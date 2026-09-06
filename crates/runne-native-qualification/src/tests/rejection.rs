use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::{NOW, context, sign, unsigned_ticket};
use crate::{
    MAX_FAULT_TICKET_BYTES, QualificationFaultError, QualificationFaultSelector,
    QualificationFaultVerifier, QualificationProcessRole,
};

fn verify(value: &serde_json::Value) -> Result<(), QualificationFaultError> {
    let key = SigningKey::from_bytes(&[7; 32]);
    QualificationFaultVerifier::for_test(key.verifying_key())
        .verify_and_consume(
            &sign(value, &key),
            &context(
                QualificationFaultSelector::BeforeNativeEffect,
                QualificationProcessRole::Service,
            ),
            NOW,
        )
        .map(|_| ())
}

#[test]
fn closed_ticket_shape_rejects_unknown_selector_and_bad_base64url() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut unknown: serde_json::Value =
        serde_json::from_slice(&sign(&unsigned_ticket(), &key)).expect("signed ticket");
    unknown["extra"] = json!(true);
    let unknown = serde_json::to_vec(&unknown).expect("mutated ticket");
    assert_eq!(
        QualificationFaultVerifier::for_test(key.verifying_key())
            .verify_and_consume(
                &unknown,
                &context(
                    QualificationFaultSelector::BeforeNativeEffect,
                    QualificationProcessRole::Service,
                ),
                NOW,
            )
            .expect_err("unknown field must fail"),
        QualificationFaultError::InvalidTicket
    );

    let mut selector = unsigned_ticket();
    selector["selector"] = json!("kill_arbitrary_process");
    assert_eq!(
        verify(&selector),
        Err(QualificationFaultError::InvalidTicket)
    );

    let mut wrong_role = unsigned_ticket();
    wrong_role["process_role"] = json!("runtime");
    assert_eq!(
        verify(&wrong_role),
        Err(QualificationFaultError::InvalidTicket)
    );

    let mut bad_run = unsigned_ticket();
    bad_run["workflow_run_id"] = json!("run/42");
    assert_eq!(
        verify(&bad_run),
        Err(QualificationFaultError::InvalidTicket)
    );

    for value in ["not+base64/", "AAAA="] {
        let mut ticket = unsigned_ticket();
        ticket["nonce"] = json!(value);
        assert_eq!(verify(&ticket), Err(QualificationFaultError::InvalidTicket));
    }
}

#[test]
fn duplicate_keys_noncanonical_wire_and_oversize_fail_before_signature() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let bytes = sign(&unsigned_ticket(), &key);
    let source = String::from_utf8(bytes).expect("utf8");
    let duplicate = source.replacen(
        '{',
        "{\"schema_version\":\"runne/macos-xpc-dpk-fault-ticket/v1\",",
        1,
    );
    let ctx = context(
        QualificationFaultSelector::BeforeNativeEffect,
        QualificationProcessRole::Service,
    );
    let mut verifier = QualificationFaultVerifier::for_test(key.verifying_key());
    assert_eq!(
        verifier
            .verify_and_consume(duplicate.as_bytes(), &ctx, NOW)
            .expect_err("duplicate must fail"),
        QualificationFaultError::InvalidTicket
    );
    let spaced = source.replacen('{', "{ ", 1);
    assert_eq!(
        verifier
            .verify_and_consume(spaced.as_bytes(), &ctx, NOW)
            .expect_err("noncanonical ticket must fail"),
        QualificationFaultError::InvalidTicket
    );
    assert_eq!(
        verifier
            .verify_and_consume(&vec![b'x'; MAX_FAULT_TICKET_BYTES + 1], &ctx, NOW)
            .expect_err("oversize must fail"),
        QualificationFaultError::InvalidTicket
    );
}

#[test]
fn exact_context_and_role_bindings_are_required() {
    for field in [
        "candidate_sha256",
        "release_tuple_v3_sha256",
        "source_revision",
        "workflow_run_id",
        "namespace_sha256",
    ] {
        let mut value = unsigned_ticket();
        value[field] = match field {
            "workflow_run_id" => json!("run-43"),
            "source_revision" => json!("00".repeat(20)),
            _ => json!("00".repeat(32)),
        };
        assert_eq!(
            verify(&value),
            Err(QualificationFaultError::ContextMismatch),
            "{field}"
        );
    }
    let key = SigningKey::from_bytes(&[7; 32]);
    let bytes = sign(&unsigned_ticket(), &key);
    for ctx in [
        context(
            QualificationFaultSelector::AfterNativeEffect,
            QualificationProcessRole::Service,
        ),
        context(
            QualificationFaultSelector::BeforeNativeEffect,
            QualificationProcessRole::Runtime,
        ),
    ] {
        assert_eq!(
            QualificationFaultVerifier::for_test(key.verifying_key())
                .verify_and_consume(&bytes, &ctx, NOW)
                .expect_err("context mismatch must fail"),
            QualificationFaultError::ContextMismatch
        );
    }
}

#[test]
fn freshness_window_rejects_stale_future_and_overlong_tickets() {
    for (issued, expires) in [
        (NOW - 901, NOW - 1),
        (NOW + 1, NOW + 10),
        (NOW, NOW + 901),
        (NOW, NOW),
    ] {
        let mut value = unsigned_ticket();
        value["issued_at"] = json!(issued);
        value["expires_at"] = json!(expires);
        assert_eq!(verify(&value), Err(QualificationFaultError::InvalidTime));
    }

    let key = SigningKey::from_bytes(&[7; 32]);
    let max_safe = 9_007_199_254_740_991_u64;
    let mut value = unsigned_ticket();
    value["issued_at"] = json!(max_safe);
    value["expires_at"] = json!(max_safe + 1);
    assert_eq!(
        QualificationFaultVerifier::for_test(key.verifying_key())
            .verify_and_consume(
                &sign(&value, &key),
                &context(
                    QualificationFaultSelector::BeforeNativeEffect,
                    QualificationProcessRole::Service,
                ),
                max_safe,
            )
            .expect_err("unsafe JSON integer must fail"),
        QualificationFaultError::InvalidTime
    );
}

#[test]
fn validly_shaped_signature_from_another_key_is_rejected() {
    let trusted = SigningKey::from_bytes(&[7; 32]);
    let attacker = SigningKey::from_bytes(&[8; 32]);
    let mut value: serde_json::Value =
        serde_json::from_slice(&sign(&unsigned_ticket(), &attacker)).expect("signed ticket");
    value["signature"]["key_id"] = json!(hex::encode(Sha256::digest(
        trusted.verifying_key().as_bytes()
    )));
    let bytes = crate::wire::test_canonical_ticket(&value).expect("canonical fake ticket");
    assert_eq!(
        QualificationFaultVerifier::for_test(trusted.verifying_key())
            .verify_and_consume(
                &bytes,
                &context(
                    QualificationFaultSelector::BeforeNativeEffect,
                    QualificationProcessRole::Service,
                ),
                NOW,
            )
            .expect_err("foreign signature must fail"),
        QualificationFaultError::InvalidSignature
    );
}

#[test]
fn signature_without_the_fault_ticket_domain_is_rejected() {
    let trusted = SigningKey::from_bytes(&[7; 32]);
    let payload = crate::wire::test_signing_payload(&unsigned_ticket()).expect("payload");
    let signature = trusted.sign(&payload[crate::wire::SIGNATURE_DOMAIN.len()..]);
    let mut value = unsigned_ticket();
    value["signature"] = json!({
        "algorithm": "ed25519",
        "key_id": hex::encode(Sha256::digest(trusted.verifying_key().as_bytes())),
        "value": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    });
    let bytes = crate::wire::test_canonical_ticket(&value).expect("canonical ticket");
    assert_eq!(
        QualificationFaultVerifier::for_test(trusted.verifying_key())
            .verify_and_consume(
                &bytes,
                &context(
                    QualificationFaultSelector::BeforeNativeEffect,
                    QualificationProcessRole::Service,
                ),
                NOW,
            )
            .expect_err("undomained signature must fail"),
        QualificationFaultError::InvalidSignature
    );
}
