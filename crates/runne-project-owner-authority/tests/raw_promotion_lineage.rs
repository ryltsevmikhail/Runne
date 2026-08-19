//! Raw promotion-chain lineage splice vectors.

use ed25519_dalek::{Signer as _, SigningKey};
use runne_project_owner_authority::{
    AuthorityError, PromotionBootstrapV4, PurposeProfileV3, RECEIPT_SCHEMA_V4,
    SignedPromotionBootstrapV4, SigningDomain, canonical_checked_in_promotion_bootstrap,
    canonical_checked_in_receipt_v3, canonical_unsigned_promotion_bootstrap,
    canonical_unsigned_receipt_v3, sign_promotion_bootstrap_v3, sign_receipt_v3_v2,
    signing_transcript, v2_platform_scope_schema_digests, verify_promotion_bootstrap_bytes,
    verify_receipt_v3_bytes,
};
use sha2::{Digest, Sha256};
use std::any::TypeId;

mod raw_promotion_support;
use raw_promotion_support::chain::{
    raw_initial, raw_predecessor, trust_v3, v2_trust, v2_trust_with_keys,
};
use raw_promotion_support::{BootstrapContext, PATHS, TestSigner, binding, subject, trust};

#[test]
fn fixture_v3_handle_is_not_a_production_v4_predecessor_handle() {
    assert_ne!(
        TypeId::of::<runne_project_owner_authority::FixtureVerifiedDocumentReconciliation>(),
        TypeId::of::<runne_project_owner_authority::VerifiedDocumentReconciliation>(),
    );
}

#[test]
fn raw_v3_rejects_an_initial_receipt_from_another_v1_lineage() {
    let (v2_key, initial_key, initial_trust, v2) = v2_trust();
    let legitimate = raw_initial(&initial_key, &initial_trust);
    let foreign_key = SigningKey::from_bytes(&[91; 32]);
    let foreign_trust = trust(&foreign_key, v2_platform_scope_schema_digests());
    let foreign = raw_initial(&foreign_key, &foreign_trust);
    let mut receipt = reconciliation(&v2, &v2_key, &legitimate);
    receipt.predecessor_receipt_sha256 = foreign.digest();
    receipt.unsigned.predecessor_receipt_sha256 = foreign.digest();
    receipt.signature = v2_key
        .sign(&signing_transcript(
            &SigningDomain::new(
                "runne.project-owner.authority-receipt/3",
                "POST_RC0_DOCUMENT_RECONCILIATION",
                "runne",
            )
            .unwrap(),
            &canonical_unsigned_receipt_v3(&receipt.unsigned).unwrap(),
        ))
        .to_bytes();
    let bytes = canonical_checked_in_receipt_v3(&receipt.unsigned, &receipt.signature).unwrap();
    receipt.project_owner_authority_receipt_sha256 = Sha256::digest(&bytes).into();
    assert_eq!(
        verify_receipt_v3_bytes(
            &bytes,
            receipt.project_owner_authority_receipt_sha256,
            &PurposeProfileV3::post_rc0_document_reconciliation(),
            &v2,
            &foreign,
        ),
        Err(AuthorityError::InvalidReceiptTrust)
    );
}

#[test]
fn raw_v4_rejects_a_reconciliation_receipt_from_another_v2_lineage() {
    let (a_key, a_initial_key, a_initial_trust, a_v2) = v2_trust();
    let predecessor_a = raw_predecessor(&a_v2, &a_key, &a_initial_key, &a_initial_trust);
    let (b_key, b_initial_key, b_initial_trust, b_v2) = v2_trust_with_keys(
        SigningKey::from_bytes(&[92; 32]),
        SigningKey::from_bytes(&[93; 32]),
    );
    let predecessor_b = raw_predecessor(&b_v2, &b_key, &b_initial_key, &b_initial_trust);
    let (root_key, v3) = trust_v3(&b_v2, &b_key);
    let mut bootstrap = bootstrap(&v3, &root_key, &predecessor_b);
    bootstrap.unsigned.predecessor_receipt_sha256 = predecessor_a.receipt_sha256();
    bootstrap.signature = root_key
        .sign(&signing_transcript(
            &SigningDomain::new(
                RECEIPT_SCHEMA_V4,
                "POST_RC0_PROMOTION_AUTHORITY_BOOTSTRAP",
                "runne",
            )
            .unwrap(),
            &canonical_unsigned_promotion_bootstrap(&bootstrap.unsigned).unwrap(),
        ))
        .to_bytes();
    let bytes = canonical_checked_in_promotion_bootstrap(&bootstrap.unsigned, &bootstrap.signature)
        .unwrap();
    bootstrap.project_owner_authority_receipt_sha256 = Sha256::digest(&bytes).into();
    assert_eq!(
        verify_promotion_bootstrap_bytes(
            &bytes,
            bootstrap.project_owner_authority_receipt_sha256,
            &v3,
            &predecessor_a,
            &BootstrapContext::valid(),
        ),
        Err(AuthorityError::InvalidReceiptTrust)
    );
}

fn reconciliation(
    trust: &runne_project_owner_authority::VerifiedTrustConfigV2,
    key: &SigningKey,
    predecessor: &runne_project_owner_authority::VerifiedInitialAuthorization,
) -> runne_project_owner_authority::SignedReceiptV3 {
    sign_receipt_v3_v2(
        &PurposeProfileV3::post_rc0_document_reconciliation(),
        trust,
        predecessor,
        subject('b'),
        PATHS
            .iter()
            .enumerate()
            .map(|(index, path)| binding(path, b"123456"[index % 6].into()))
            .collect(),
        "2026-08-13T00:00:01Z".into(),
        &TestSigner(key.clone()),
    )
    .unwrap()
}

fn bootstrap(
    trust: &runne_project_owner_authority::VerifiedTrustConfigV3,
    key: &SigningKey,
    predecessor: &runne_project_owner_authority::VerifiedDocumentReconciliation,
) -> SignedPromotionBootstrapV4 {
    sign_promotion_bootstrap_v3(
        trust,
        predecessor,
        PromotionBootstrapV4 {
            schema_version: RECEIPT_SCHEMA_V4.into(),
            repository_id: "runne".into(),
            role: "PROJECT_OWNER".into(),
            purpose: "POST_RC0_PROMOTION_AUTHORITY_BOOTSTRAP".into(),
            profile: "runne.project-owner.post-rc0-promotion/1".into(),
            predecessor_receipt_sha256: predecessor.receipt_sha256(),
            platform_qualified_subject_sha256: [2; 32],
            platform_matrix_sha256: [3; 32],
            promotion_policy_sha256: [4; 32],
            promotion_policy_revision: "policy-1".into(),
            authority_store_profile: "store-1".into(),
            root_principal_id: "root-principal".into(),
            root_controlling_account_id: "root-account".into(),
            root_lane_id: "root-lane".into(),
            root_signature_profile_id: "root-profile".into(),
            issued_at: "2026-08-13T00:00:00Z".into(),
            not_before: "2026-08-13T00:00:01Z".into(),
            expires_at: "2026-08-13T00:00:04Z".into(),
            revocation_epoch: 1,
            delegations: [
                ("RC1_QUALIFICATION_AUTHORIZER", 50),
                ("RC2_SIGNING_AUTHORIZER", 51),
                ("RC3_PUBLICATION_AUTHORIZER", 52),
            ]
            .into_iter()
            .map(|(role, seed)| {
                raw_promotion_support::chain::delegation(role, &SigningKey::from_bytes(&[seed; 32]))
            })
            .collect(),
            subject: runne_project_owner_authority::GitSubject {
                object_format: "sha1".into(),
                commit_oid: "5".repeat(40),
                tree_oid: "6".repeat(40),
            },
            documents: vec![
                runne_project_owner_authority::Document {
                    path: "docs/adr/ADR-0028-promotion-and-release-authority-v2.md".into(),
                    mode: "100644".into(),
                    blob_oid: "3b7212501922c71abfa3b3fc4dcf6ae879de87bb".into(),
                    content_sha256:
                        "a26a9e3e0abe91fd7dd149aa70e69acc98bf7d88a7a16f1a4ecdfad958b447a9".into(),
                    byte_length: 5_974,
                    schema_id: None,
                },
                runne_project_owner_authority::Document {
                    path: "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md"
                        .into(),
                    mode: "100644".into(),
                    blob_oid: "7dc041799a2187633998a5883cac14221feda73b".into(),
                    content_sha256:
                        "281599b27a9c578291527ca6e056de9369073e006687dd1149420d83a2cc86b9".into(),
                    byte_length: 26_202,
                    schema_id: None,
                },
            ],
            trust_config_sha256: String::new(),
            key_id: String::new(),
            key_epoch: 0,
        },
        &TestSigner(key.clone()),
    )
    .unwrap()
}
