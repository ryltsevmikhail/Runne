use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use super::{NOW, sign, sign_run_context, unsigned_run_context, unsigned_ticket};
use crate::{QualificationRunContextVerifier, VerifiedQualificationRunContext};

#[test]
fn valid_runner_context_is_verified_once_and_yields_fence_identities() {
    let fault_key = SigningKey::from_bytes(&[7; 32]);
    let context_key = SigningKey::from_bytes(&[9; 32]);
    let ticket = sign(&unsigned_ticket(), &fault_key);
    let ticket_sha256 = Sha256::digest(&ticket).into();
    let context = sign_run_context(&unsigned_run_context(ticket_sha256), &context_key);
    let golden = include_bytes!("../../../../docs/golden/macos-xpc-dpk-run-context-v1.json");
    assert_eq!(
        context.as_slice(),
        golden.strip_suffix(b"\n").unwrap_or(golden)
    );
    let expected = super::run_context_expectation(ticket_sha256);
    let mut authority = QualificationRunContextVerifier::for_test(context_key.verifying_key());

    let verified: VerifiedQualificationRunContext = authority
        .verify_and_consume(&context, &expected, NOW)
        .expect("valid independently signed runner context");
    assert_eq!(verified.context_id(), [0x33; 32]);
    assert_eq!(verified.nonce(), [0x44; 32]);
    assert_eq!(verified.expires_at(), NOW + 300);
    assert_eq!(verified.ticket_sha256(), ticket_sha256);
    assert!(
        authority
            .verify_and_consume(&context, &expected, NOW)
            .is_err()
    );
}

#[test]
fn runner_context_nonce_cannot_be_replayed_with_a_new_context_id() {
    let key = SigningKey::from_bytes(&[9; 32]);
    let digest = [0x55; 32];
    let first = sign_run_context(&unsigned_run_context(digest), &key);
    let mut second_value = unsigned_run_context(digest);
    second_value["context_id"] = serde_json::json!("66".repeat(32));
    let second = sign_run_context(&second_value, &key);
    let expected = super::run_context_expectation(digest);
    let mut authority = QualificationRunContextVerifier::for_test(key.verifying_key());
    authority
        .verify_and_consume(&first, &expected, NOW)
        .expect("first context");
    assert_eq!(
        authority.verify_and_consume(&second, &expected, NOW).err(),
        Some(crate::QualificationRunContextError::Replay)
    );
}

#[test]
fn context_policy_is_independent_and_disabled_when_unprovisioned() {
    let fault_key = SigningKey::from_bytes(&[7; 32]);
    let context_key = SigningKey::from_bytes(&[9; 32]);
    let ticket = sign(&unsigned_ticket(), &fault_key);
    let ticket_sha256 = Sha256::digest(&ticket).into();
    let context = sign_run_context(&unsigned_run_context(ticket_sha256), &context_key);
    let error = QualificationRunContextVerifier::from_compiled_policy()
        .verify_and_consume(
            &context,
            &super::run_context_expectation(ticket_sha256),
            NOW,
        )
        .err()
        .expect("missing context policy remains inert");
    assert_eq!(
        error,
        crate::QualificationRunContextError::PolicyUnavailable
    );
}
