use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{NOW, admission_bundle, sign, sign_run_context, unsigned_run_context, unsigned_ticket};
use crate::{
    PendingQualificationAdmission, QualificationAdmissionVerificationError,
    QualificationAdmissionVerifier,
};

fn signed_pair(
    context_change: impl FnOnce(&mut Value),
    ticket_change: impl FnOnce(&mut Value),
) -> PendingQualificationAdmission {
    let fault_key = SigningKey::from_bytes(&[7; 32]);
    let context_key = SigningKey::from_bytes(&[9; 32]);
    let mut ticket = unsigned_ticket();
    ticket_change(&mut ticket);
    let ticket = sign(&ticket, &fault_key);
    let mut context = unsigned_run_context(Sha256::digest(&ticket).into());
    context_change(&mut context);
    let context = sign_run_context(&context, &context_key);
    PendingQualificationAdmission::from_admitted_bundle(admission_bundle(&context, &ticket))
        .expect("internally consistent signed pair")
}

#[derive(Clone, Copy)]
struct InstalledFacts {
    candidate: [u8; 32],
    raw_tuple: [u8; 32],
}

const fn expected() -> InstalledFacts {
    InstalledFacts {
        candidate: [0xaa; 32],
        raw_tuple: [0xbb; 32],
    }
}

fn verify(
    verifier: &mut QualificationAdmissionVerifier,
    admission: PendingQualificationAdmission,
    installed: InstalledFacts,
    now: u64,
) -> Result<(), QualificationAdmissionVerificationError> {
    verifier.verify_and_consume(admission, installed.candidate, installed.raw_tuple, now)
}

fn verifier() -> QualificationAdmissionVerifier {
    QualificationAdmissionVerifier::for_test(
        SigningKey::from_bytes(&[9; 32]).verifying_key(),
        SigningKey::from_bytes(&[7; 32]).verifying_key(),
    )
}

#[test]
fn correctly_signed_pair_is_accepted_once_without_authority() {
    let mut verifier = verifier();
    verify(&mut verifier, signed_pair(|_| {}, |_| {}), expected(), NOW).expect("valid pair");
    assert!(
        verify(&mut verifier, signed_pair(|_| {}, |_| {}), expected(), NOW,).is_err(),
        "context and ticket identities are single-use"
    );
}

#[test]
fn installed_expectation_rejects_zero_and_crossed_candidate_or_raw_tuple() {
    let pair = || signed_pair(|_| {}, |_| {});
    assert!(
        verifier()
            .verify_and_consume(pair(), [0; 32], [2; 32], NOW)
            .is_err()
    );
    assert!(
        verifier()
            .verify_and_consume(pair(), [1; 32], [0; 32], NOW)
            .is_err()
    );
    for crossed in [
        InstalledFacts {
            candidate: [0xab; 32],
            raw_tuple: [0xbb; 32],
        },
        InstalledFacts {
            candidate: [0xaa; 32],
            raw_tuple: [0xbc; 32],
        },
    ] {
        assert!(verify(&mut verifier(), pair(), crossed, NOW).is_err());
    }
}

#[test]
fn qualified_release_binding_cannot_substitute_for_raw_tuple() {
    let pair = signed_pair(
        |context| context["release_tuple_v3_sha256"] = json!("ee".repeat(32)),
        |_| {},
    );
    assert!(verify(&mut verifier(), pair, expected(), NOW).is_err());
}

#[test]
fn context_is_the_only_authority_for_every_ticket_assertion() {
    let cases = [
        ("selector", json!("kill_after_native_effect")),
        ("candidate_sha256", json!("ab".repeat(32))),
        ("release_tuple_v3_sha256", json!("bc".repeat(32))),
        ("source_revision", json!("cd".repeat(20))),
        ("workflow_run_id", json!("run-43")),
        ("namespace_sha256", json!("de".repeat(32))),
    ];
    for (field, replacement) in cases {
        let pair = signed_pair(|_| {}, |ticket| ticket[field] = replacement);
        assert!(
            verify(&mut verifier(), pair, expected(), NOW).is_err(),
            "ticket {field} escaped context binding"
        );
    }
    let role_pair = signed_pair(
        |_| {},
        |ticket| {
            ticket["selector"] = json!("kill_runtime_process");
            ticket["process_role"] = json!("runtime");
        },
    );
    assert!(
        verify(&mut verifier(), role_pair, expected(), NOW).is_err(),
        "a different valid selector/role pair escaped context binding"
    );
}

#[test]
fn combined_verifier_rejects_unavailable_colliding_or_invalid_authorities_and_time() {
    assert!(
        verify(
            &mut QualificationAdmissionVerifier::from_compiled_policy(),
            signed_pair(|_| {}, |_| {}),
            expected(),
            NOW,
        )
        .is_err()
    );
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    assert!(
        verify(
            &mut QualificationAdmissionVerifier::for_test(key, key),
            signed_pair(|_| {}, |_| {}),
            expected(),
            NOW,
        )
        .is_err()
    );
    assert!(
        verify(
            &mut verifier(),
            signed_pair(|context| context["issued_at"] = json!(NOW + 1), |_| {}),
            expected(),
            NOW,
        )
        .is_err()
    );
    assert!(
        verify(
            &mut verifier(),
            signed_pair(|_| {}, |ticket| ticket["issued_at"] = json!(NOW + 1)),
            expected(),
            NOW,
        )
        .is_err()
    );
}

#[test]
fn combined_verifier_rejects_each_invalid_signature_and_stale_member() {
    let fault_key = SigningKey::from_bytes(&[7; 32]);
    let context_key = SigningKey::from_bytes(&[9; 32]);
    let ticket = sign(&unsigned_ticket(), &fault_key);
    let ticket_sha256 = Sha256::digest(&ticket).into();
    let foreign_context = sign_run_context(
        &unsigned_run_context(ticket_sha256),
        &SigningKey::from_bytes(&[10; 32]),
    );
    let foreign_context = PendingQualificationAdmission::from_admitted_bundle(admission_bundle(
        &foreign_context,
        &ticket,
    ))
    .unwrap();
    assert!(verify(&mut verifier(), foreign_context, expected(), NOW).is_err());

    let foreign_ticket = sign(&unsigned_ticket(), &SigningKey::from_bytes(&[8; 32]));
    let context = sign_run_context(
        &unsigned_run_context(Sha256::digest(&foreign_ticket).into()),
        &context_key,
    );
    let foreign_ticket = PendingQualificationAdmission::from_admitted_bundle(admission_bundle(
        &context,
        &foreign_ticket,
    ))
    .unwrap();
    assert!(verify(&mut verifier(), foreign_ticket, expected(), NOW).is_err());

    let stale = signed_pair(
        |context| {
            context["issued_at"] = json!(NOW - 601);
            context["expires_at"] = json!(NOW);
        },
        |_| {},
    );
    assert!(verify(&mut verifier(), stale, expected(), NOW).is_err());
}

#[test]
fn ticket_replay_fails_even_under_a_fresh_valid_context_identity() {
    let fault_key = SigningKey::from_bytes(&[7; 32]);
    let context_key = SigningKey::from_bytes(&[9; 32]);
    let ticket = sign(&unsigned_ticket(), &fault_key);
    let digest = Sha256::digest(&ticket).into();
    let first = sign_run_context(&unsigned_run_context(digest), &context_key);
    let mut second = unsigned_run_context(digest);
    second["context_id"] = json!("55".repeat(32));
    second["nonce"] = json!(URL_SAFE_NO_PAD.encode([0x66; 32]));
    let second = sign_run_context(&second, &context_key);
    let mut verifier = verifier();
    for (index, context) in [first, second].into_iter().enumerate() {
        let pair = PendingQualificationAdmission::from_admitted_bundle(admission_bundle(
            &context, &ticket,
        ))
        .unwrap();
        let result = verify(&mut verifier, pair, expected(), NOW);
        assert_eq!(result.is_ok(), index == 0);
    }
}
