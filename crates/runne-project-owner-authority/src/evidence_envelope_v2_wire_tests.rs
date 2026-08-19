//! Raw evidence-envelope `/2` verification tests including the RC3 specialization.

#![allow(clippy::semicolon_if_nothing_returned, clippy::redundant_clone)]

use std::cell::{Cell, RefCell};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::v5_envelope_test_support::*;
use crate::{
    AuthorityError, EVIDENCE_ENVELOPE_SCHEMA_V2, EvidenceAuthorityEnvelopeV2,
    verify_evidence_envelope_v2, verify_rc3_final_review_evidence_v2,
};

type Mutation = (
    &'static str,
    Box<dyn Fn(&mut EvidenceAuthorityEnvelopeV2)>,
    AuthorityError,
);

#[test]
fn valid_evidence_envelope_v2_verifies_full_raw_chain_and_calls_context_once() {
    let chain = chain();
    let (envelope, key) = evidence_envelope(&chain.receipt5, "RC3_FINAL_REVIEWER", "final-review");
    let bytes = signed_evidence_v2(&envelope, &key);
    let context = EnvelopeContext(Cell::new(0));
    let verified = verify_evidence_envelope_v2(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &chain.receipt5,
        &context,
    )
    .unwrap();
    assert_eq!(
        verified.envelope_sha256(),
        <[u8; 32]>::from(Sha256::digest(&bytes[..bytes.len() - 1]))
    );
    assert_eq!(verified.receipt_sha256(), chain.receipt5.receipt_sha256());
    assert_eq!(verified.trust_generation(), 4);
    assert_eq!(
        verified.payload_schema_id(),
        "runne.release.rc3-final-review/1"
    );
    assert_eq!(
        verified.payload(),
        crate::canonical_stage_payload(&envelope.payload).unwrap()
    );
    assert_eq!(verified.issuer().role, "RC3_FINAL_REVIEWER");
    assert_eq!(verified.issuer().scope, "final-review");
    assert_eq!(context.0.get(), 1);
}

#[test]
fn rc3_final_review_specialization_requires_exact_role_scope_and_schema() {
    let chain = chain();
    let (final_review, key) =
        evidence_envelope(&chain.receipt5, "RC3_FINAL_REVIEWER", "final-review");
    let bytes = signed_evidence_v2(&final_review, &key);
    let context = EnvelopeContext(Cell::new(0));
    let verified = verify_rc3_final_review_evidence_v2(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &chain.receipt5,
        &context,
    )
    .unwrap();
    assert_eq!(
        verified.payload_schema_id(),
        "runne.release.rc3-final-review/1"
    );
    assert_eq!(context.0.get(), 1);
    let (native, key) = evidence_envelope(&chain.receipt5, "RC2_NATIVE_EVIDENCE", "linux");
    let bytes = signed_evidence_v2(&native, &key);
    let generic = EnvelopeContext(Cell::new(0));
    assert!(
        verify_evidence_envelope_v2(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &chain.receipt5,
            &generic
        )
        .is_ok()
    );
    let specialized = EnvelopeContext(Cell::new(0));
    assert_eq!(
        verify_rc3_final_review_evidence_v2(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &chain.receipt5,
            &specialized
        ),
        Err(AuthorityError::InvalidEvidenceEnvelope)
    );
}

#[test]
fn legacy_or_mixed_envelope_versions_are_rejected_before_context() {
    let chain = chain();
    let (mut envelope, key) =
        evidence_envelope(&chain.receipt5, "RC3_FINAL_REVIEWER", "final-review");
    envelope.schema_version = "runne.release.post-rc0-stage-envelope/2".into();
    let bytes = signed_evidence_v2(&envelope, &key);
    let context = EnvelopeContext(Cell::new(0));
    assert_eq!(
        verify_evidence_envelope_v2(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &chain.receipt5,
            &context
        ),
        Err(AuthorityError::AuthorityVersionSuperseded)
    );
    assert_eq!(context.0.get(), 0);
}

#[test]
fn malformed_or_wrong_digest_bytes_never_reach_context() {
    let chain = chain();
    let (envelope, key) = evidence_envelope(&chain.receipt5, "RC3_FINAL_REVIEWER", "final-review");
    let bytes = signed_evidence_v2(&envelope, &key);
    let context = EnvelopeContext(Cell::new(0));
    let crlf = String::from_utf8(bytes.clone())
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();
    assert_eq!(
        verify_evidence_envelope_v2(
            &crlf,
            Sha256::digest(&crlf[..crlf.len() - 2]).into(),
            &chain.receipt5,
            &context
        ),
        Err(AuthorityError::InvalidCanonicalReceipt)
    );
    assert_eq!(context.0.get(), 0);
    assert_eq!(
        verify_evidence_envelope_v2(&bytes, [0; 32], &chain.receipt5, &context),
        Err(AuthorityError::InvalidReceiptDigest)
    );
    assert_eq!(context.0.get(), 0);
    let mut malformed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    malformed["signature"] = serde_json::Value::String("A".into());
    let mut malformed = serde_json::to_vec(&malformed).unwrap();
    malformed.push(b'\n');
    assert_eq!(
        verify_evidence_envelope_v2(
            &malformed,
            Sha256::digest(&malformed[..malformed.len() - 1]).into(),
            &chain.receipt5,
            &context
        ),
        Err(AuthorityError::InvalidReceiptSignature)
    );
    assert_eq!(context.0.get(), 0);
}

#[test]
fn evidence_mutations_are_rejected_before_context() {
    let chain = chain();
    let (envelope, key) = evidence_envelope(&chain.receipt5, "RC3_FINAL_REVIEWER", "final-review");
    let other = SigningKey::from_bytes(&[9; 32]);
    let root_key_id =
        crate::trust_canonical::hex(&crate::key_id(&chain.root.verifying_key().to_bytes()));
    let mutations: Vec<Mutation> = include!("evidence_envelope_v2_mutations.rs");
    for (name, mutate, expected) in mutations {
        let mut changed = envelope.clone();
        mutate(&mut changed);
        let bytes = signed_evidence_v2(&changed, &key);
        let context = EnvelopeContext(Cell::new(0));
        assert_eq!(
            verify_evidence_envelope_v2(
                &bytes,
                Sha256::digest(&bytes[..bytes.len() - 1]).into(),
                &chain.receipt5,
                &context
            ),
            Err(expected),
            "{name} must be rejected before context admission"
        );
        assert_eq!(context.0.get(), 0, "{name} must not reach context");
    }
}

#[test]
fn nonce_replay_and_context_rejection_are_propagated() {
    let chain = chain();
    let (envelope, key) = evidence_envelope(&chain.receipt5, "RC3_FINAL_REVIEWER", "final-review");
    let bytes = signed_evidence_v2(&envelope, &key);
    let digest = Sha256::digest(&bytes[..bytes.len() - 1]).into();
    let replay = ReplayEnvelopeContext(RefCell::new(Vec::new()));
    assert!(verify_evidence_envelope_v2(&bytes, digest, &chain.receipt5, &replay).is_ok());
    assert_eq!(
        verify_evidence_envelope_v2(&bytes, digest, &chain.receipt5, &replay),
        Err(AuthorityError::ReplayedStageEnvelope)
    );
    let rejecting = RejectingEnvelopeContext(Cell::new(0));
    assert_eq!(
        verify_evidence_envelope_v2(&bytes, digest, &chain.receipt5, &rejecting),
        Err(AuthorityError::StaleOrRevokedStageEnvelope)
    );
    assert_eq!(rejecting.0.get(), 1);
}

#[test]
fn verified_evidence_envelope_v2_is_move_only() {
    let chain = chain();
    let (envelope, key) = evidence_envelope(&chain.receipt5, "RC3_FINAL_REVIEWER", "final-review");
    let bytes = signed_evidence_v2(&envelope, &key);
    let verified = verify_evidence_envelope_v2(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &chain.receipt5,
        &EnvelopeContext(Cell::new(0)),
    )
    .unwrap();
    let moved = move || verified.envelope_sha256();
    let _ = moved();
    assert_eq!(
        EVIDENCE_ENVELOPE_SCHEMA_V2,
        "runne.release.post-rc0-evidence-envelope/2"
    );
}
