use std::cell::Cell;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, GitSubject, PromotionAuthorityReceiptV5, V5_EVIDENCE_ROLE_SCOPES,
    V5_TRANSITION_ROLES, verify_promotion_authority_receipt_v5,
};

#[path = "receipt_v5_wire_test_support.rs"]
pub mod support;
use support::*;

type Mutation = (&'static str, fn(&mut PromotionAuthorityReceiptV5));

#[test]
#[ignore = "requires unpublished historical source documents"]
fn v5_document_pins_match_historical_source_files() {
    use crate::receipt_v5_document_profile::{ADR_0029_SHA256 as ADR, PROGRAM_SHA256 as PROGRAM};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs");
    let files = [
        "adr/ADR-0029-versioned-promotion-trust-and-evidence-authority.md",
        "superpowers/specs/2026-08-13-post-rc0-delivery-program-design-v2.md",
    ];
    for (file, expected) in files.into_iter().zip([ADR, PROGRAM]) {
        let path = root.join(file);
        let bytes = std::fs::read(&path).unwrap_or_else(|error| {
            panic!("requires original unpublished historical source {path:?}: {error}")
        });
        assert_eq!(<[u8; 32]>::from(Sha256::digest(bytes)), expected);
    }
}
#[test]
fn v5_document_pins_and_payload_schema_sets_match_checked_in_schema_files() {
    let review_digest: [u8; 32] = Sha256::digest(include_bytes!(
        "../../../docs/schemas/rc0-production-security-review-v1.schema.json"
    ))
    .into();
    assert_eq!(
        review_digest,
        crate::receipt_v5_document_profile::PRODUCTION_SECURITY_REVIEW_SHA256
    );
    let allowlist_digest: [u8; 32] = Sha256::digest(include_bytes!(
        "../../../docs/schemas/project-owner-publication-destination-allowlist-v1.schema.json"
    ))
    .into();
    assert_eq!(
        allowlist_digest,
        crate::receipt_v5_document_profile::INITIAL_DESTINATION_ALLOWLIST_SHA256
    );
    assert_eq!(
        crate::receipt_v5_document_profile::INITIAL_DESTINATION_ALLOWLIST_GENERATION,
        1
    );
    for (role, scope) in V5_TRANSITION_ROLES.iter().map(|role| (*role, "transition")) {
        assert_eq!(
            crate::receipt_v5_validation::allowed_payload_schemas(role, scope),
            expected_schemas(role, scope)
        );
    }
    for (role, scope) in V5_EVIDENCE_ROLE_SCOPES {
        assert_eq!(
            crate::receipt_v5_validation::allowed_payload_schemas(role, scope),
            expected_schemas(role, scope)
        );
    }
}

#[test]
fn raw_receipt_v5_verifies_signature_lineage_closure_then_calls_context_once() {
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = trust(&root, [1; 32]);
    let predecessor = predecessor(&subject(), crate::trust_canonical::hex(&[1; 32]));
    let receipt = receipt(&trust);
    let bytes = signed_bytes(&root, &receipt);
    let context = Context(Cell::new(0));
    let verified = verify_promotion_authority_receipt_v5(
        &bytes,
        Sha256::digest(&bytes).into(),
        &trust,
        &predecessor,
        &expected(&receipt),
        &context,
    )
    .unwrap();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(verified.receipt_sha256(), digest);
    assert_eq!(verified.bindings().subject(), &subject());
    assert_eq!(
        verified.bindings().production_security_review_sha256(),
        crate::receipt_v5_document_profile::PRODUCTION_SECURITY_REVIEW_SHA256
    );
    assert_eq!(
        verified.bindings().destination_allowlist_sha256(),
        crate::receipt_v5_document_profile::INITIAL_DESTINATION_ALLOWLIST_SHA256
    );
    assert_eq!(context.0.get(), 1);
}

#[test]
fn malformed_bytes_wrong_digest_or_signature_never_reach_context() {
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = trust(&root, [1; 32]);
    let predecessor = predecessor(&subject(), crate::trust_canonical::hex(&[1; 32]));
    let bytes = signed_bytes(&root, &receipt(&trust));
    let expected = expected(&receipt(&trust));
    let mut malformed = bytes.clone();
    malformed[0] ^= 1;
    let context = Context(Cell::new(0));
    assert!(
        verify_promotion_authority_receipt_v5(
            &malformed,
            Sha256::digest(&malformed).into(),
            &trust,
            &predecessor,
            &expected,
            &context
        )
        .is_err()
    );
    assert_eq!(context.0.get(), 0);
    let wrong_key = SigningKey::from_bytes(&[9; 32]);
    let forged = signed_bytes(&wrong_key, &receipt(&trust));
    assert_eq!(
        verify_promotion_authority_receipt_v5(
            &forged,
            Sha256::digest(&forged).into(),
            &trust,
            &predecessor,
            &expected,
            &context
        ),
        Err(AuthorityError::InvalidReceiptSignature)
    );
    assert_eq!(context.0.get(), 0);
    assert_eq!(
        verify_promotion_authority_receipt_v5(
            &bytes,
            [0; 32],
            &trust,
            &predecessor,
            &expected,
            &context,
        ),
        Err(AuthorityError::InvalidReceiptDigest)
    );
    assert_eq!(context.0.get(), 0);
}

#[test]
fn trust_v4_predecessor_splice_from_receipt4_v3_scope_is_rejected_before_context() {
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = trust(&root, [2; 32]);
    let predecessor = predecessor(&subject(), crate::trust_canonical::hex(&[1; 32]));
    let bytes = signed_bytes(&root, &receipt(&trust));
    let expected = expected(&receipt(&trust));
    let context = Context(Cell::new(0));
    assert_eq!(
        verify_promotion_authority_receipt_v5(
            &bytes,
            Sha256::digest(&bytes).into(),
            &trust,
            &predecessor,
            &expected,
            &context
        ),
        Err(AuthorityError::InvalidReceiptTrust)
    );
    assert_eq!(context.0.get(), 0);
}

#[test]
fn wrong_expected_inputs_are_rejected_before_context() {
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = trust(&root, [1; 32]);
    let predecessor = predecessor(&subject(), crate::trust_canonical::hex(&[1; 32]));
    let base = receipt(&trust);
    let expected = expected(&base);
    let mutations: Vec<Mutation> = vec![
        ("production security review", |receipt| {
            receipt.production_security_review_sha256 = [0; 32];
        }),
        ("destination allowlist digest", |receipt| {
            receipt.destination_allowlist_sha256 = [0; 32];
        }),
        ("destination allowlist generation", |receipt| {
            receipt.destination_allowlist_generation = 2;
        }),
        ("source subject", |receipt| {
            receipt.subject = GitSubject {
                object_format: "sha1".into(),
                commit_oid: "c".repeat(40),
                tree_oid: "d".repeat(40),
            }
        }),
        ("active program digest", |receipt| {
            receipt.post_rc0_program_sha256 = [0; 32];
        }),
    ];
    for (name, mutate) in mutations {
        let mut changed = base.clone();
        mutate(&mut changed);
        let bytes = signed_bytes(&root, &changed);
        let context = Context(Cell::new(0));
        assert_eq!(
            verify_promotion_authority_receipt_v5(
                &bytes,
                Sha256::digest(&bytes).into(),
                &trust,
                &predecessor,
                &expected,
                &context
            ),
            Err(AuthorityError::InvalidReceiptTrust),
            "{name} must be rejected before context admission"
        );
        assert_eq!(context.0.get(), 0, "{name} must not reach context");
    }
}

#[test]
fn non_exact_payload_schema_sets_are_rejected_before_context() {
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = trust(&root, [1; 32]);
    let predecessor = predecessor(&subject(), crate::trust_canonical::hex(&[1; 32]));
    let mut missing = receipt(&trust);
    missing.transition_delegations[0]
        .allowed_payload_schema_ids
        .clear();
    assert_rejected_before_context(&root, &trust, &predecessor, &missing);
    let mut extra = receipt(&trust);
    extra.transition_delegations[1].allowed_payload_schema_ids = vec![
        "gocode.release.rc2-signing-authorization/1".into(),
        "gocode.other/1".into(),
    ];
    assert_rejected_before_context(&root, &trust, &predecessor, &extra);
    let mut cross_role = receipt(&trust);
    cross_role.evidence_delegations[4].allowed_payload_schema_ids =
        vec!["gocode.release.rc2-signing-authorization/1".into()];
    assert_rejected_before_context(&root, &trust, &predecessor, &cross_role);
}

#[test]
fn receipt_v5_rejects_schema_digest_as_allowlist_instance_before_context() {
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = trust(&root, [1; 32]);
    let predecessor = predecessor(&subject(), crate::trust_canonical::hex(&[1; 32]));
    let mut value = receipt(&trust);
    value.destination_allowlist_sha256 = [8; 32];
    let bytes = signed_bytes(&root, &value);
    let expected = crate::ExpectedReceiptV5Bindings::test_only(
        value.production_security_review_sha256,
        value.subject.clone(),
        crate::receipt_v5_document_profile::INITIAL_DESTINATION_ALLOWLIST_SHA256,
        value.destination_allowlist_generation,
    );
    let context = Context(Cell::new(0));
    assert_eq!(
        verify_promotion_authority_receipt_v5(
            &bytes,
            Sha256::digest(&bytes).into(),
            &trust,
            &predecessor,
            &expected,
            &context,
        ),
        Err(AuthorityError::InvalidReceiptTrust)
    );
    assert_eq!(context.0.get(), 0);
}

#[test]
fn receipt_v5_accepts_matching_synthetic_allowlist_instance() {
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = trust(&root, [1; 32]);
    let predecessor = predecessor(&subject(), crate::trust_canonical::hex(&[1; 32]));
    let mut value = receipt(&trust);
    value.destination_allowlist_sha256 = [8; 32];
    let bytes = signed_bytes(&root, &value);
    let expected = crate::ExpectedReceiptV5Bindings::test_only(
        value.production_security_review_sha256,
        value.subject.clone(),
        value.destination_allowlist_sha256,
        value.destination_allowlist_generation,
    );
    let context = Context(Cell::new(0));
    assert!(
        verify_promotion_authority_receipt_v5(
            &bytes,
            Sha256::digest(&bytes).into(),
            &trust,
            &predecessor,
            &expected,
            &context,
        )
        .is_ok()
    );
    assert_eq!(context.0.get(), 1);
}
