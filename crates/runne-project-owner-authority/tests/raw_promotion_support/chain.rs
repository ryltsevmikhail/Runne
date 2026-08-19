use ed25519_dalek::{Signer as _, SigningKey};
use runne_project_owner_authority::{
    DelegationV1, Document, GitSubject, KeyRotationV2, KeyRotationV3, ProjectOwnerTrustConfigV1,
    PromotionBootstrapV4, PurposeProfileV2, PurposeProfileV3, RECEIPT_SCHEMA_V4,
    SignedPromotionBootstrapV4, VerifiedInitialAuthorization, VerifiedTrustConfigV2,
    VerifiedTrustConfigV3, canonical_checked_in_receipt, canonical_checked_in_receipt_v3, key_id,
    rotation_v2_new_pop_transcript, rotation_v2_old_authorization_transcript,
    rotation_v3_new_pop_transcript, rotation_v3_old_authorization_transcript,
    sign_promotion_bootstrap_v3, sign_receipt_v2, sign_receipt_v3_v2,
    v2_platform_scope_schema_digests, v2_trust_schema_digests, v3_trust_schema_digests,
    verify_initial_authorization_v2_bytes, verify_receipt_v3_bytes, verify_trust_upgrade_v1_to_v2,
    verify_trust_upgrade_v2_to_v3,
};

use super::{PATHS, TestSigner, anchor, binding, subject, trust, v2_documents};

pub fn v2_trust() -> (
    SigningKey,
    SigningKey,
    ProjectOwnerTrustConfigV1,
    VerifiedTrustConfigV2,
) {
    v2_trust_with_keys(
        SigningKey::from_bytes(&[41; 32]),
        SigningKey::from_bytes(&[42; 32]),
    )
}

pub fn v2_trust_with_keys(
    old_key: SigningKey,
    new_key: SigningKey,
) -> (
    SigningKey,
    SigningKey,
    ProjectOwnerTrustConfigV1,
    VerifiedTrustConfigV2,
) {
    let old = trust(&old_key, v2_platform_scope_schema_digests());
    let mut rotation = KeyRotationV2 {
        schema_version: "runne.project-owner.key-rotation/2".into(),
        repository_id: "runne".into(),
        role: "PROJECT_OWNER".into(),
        old_trust_schema_version: old.schema_version.clone(),
        old_trust_config_sha256: old.sha256().unwrap(),
        old_key_id: old.key_id,
        old_epoch: old.epoch,
        new_trust_schema_version: "runne.project-owner.trust-config/2".into(),
        new_key_id: key_id(&new_key.verifying_key().to_bytes()),
        new_public_key: new_key.verifying_key().to_bytes(),
        new_epoch: 2,
        new_schema_digests: v2_trust_schema_digests(),
        old_authorization: [0; 64],
        new_proof_of_possession: [0; 64],
    };
    rotation.new_proof_of_possession = new_key
        .sign(&rotation_v2_new_pop_transcript(&old, &rotation).unwrap())
        .to_bytes();
    rotation.old_authorization = old_key
        .sign(&rotation_v2_old_authorization_transcript(&rotation).unwrap())
        .to_bytes();
    (
        new_key,
        old_key,
        old.clone(),
        verify_trust_upgrade_v1_to_v2(&old, &rotation).unwrap(),
    )
}

pub fn raw_initial(
    initial_key: &SigningKey,
    initial_trust: &ProjectOwnerTrustConfigV1,
) -> VerifiedInitialAuthorization {
    let initial = sign_receipt_v2(
        &PurposeProfileV2::v1_platform_scope(),
        initial_trust,
        &anchor(initial_trust),
        subject('a'),
        v2_documents(),
        "2026-08-13T00:00:00Z".into(),
        &TestSigner(initial_key.clone()),
    )
    .unwrap();
    let initial_bytes =
        canonical_checked_in_receipt(&initial.unsigned, &initial.signature).unwrap();
    verify_initial_authorization_v2_bytes(
        &initial_bytes,
        initial.project_owner_authority_receipt_sha256,
        initial_trust,
        &anchor(initial_trust),
    )
    .unwrap()
}

pub fn raw_predecessor(
    trust_v2: &VerifiedTrustConfigV2,
    signer: &SigningKey,
    initial_key: &SigningKey,
    initial_trust: &ProjectOwnerTrustConfigV1,
) -> runne_project_owner_authority::VerifiedDocumentReconciliation {
    let initial = raw_initial(initial_key, initial_trust);
    let receipt = sign_receipt_v3_v2(
        &PurposeProfileV3::post_rc0_document_reconciliation(),
        trust_v2,
        &initial,
        subject('b'),
        PATHS
            .iter()
            .enumerate()
            .map(|(index, path)| binding(path, b"123456"[index % 6].into()))
            .collect(),
        "2026-08-13T00:00:01Z".into(),
        &TestSigner(signer.clone()),
    )
    .unwrap();
    let bytes = canonical_checked_in_receipt_v3(&receipt.unsigned, &receipt.signature).unwrap();
    verify_receipt_v3_bytes(
        &bytes,
        receipt.project_owner_authority_receipt_sha256,
        &PurposeProfileV3::post_rc0_document_reconciliation(),
        trust_v2,
        &initial,
    )
    .unwrap()
}

pub fn trust_v3(
    old: &VerifiedTrustConfigV2,
    old_key: &SigningKey,
) -> (SigningKey, VerifiedTrustConfigV3) {
    let new_key = SigningKey::from_bytes(&[43; 32]);
    let mut rotation = KeyRotationV3 {
        schema_version: "runne.project-owner.key-rotation/3".into(),
        repository_id: "runne".into(),
        role: "PROJECT_OWNER".into(),
        old_trust_schema_version: old.schema_version.clone(),
        old_trust_config_sha256: old.sha256().unwrap(),
        old_key_id: old.key_id,
        old_epoch: old.epoch,
        new_trust_schema_version: "runne.project-owner.trust-config/3".into(),
        new_key_id: key_id(&new_key.verifying_key().to_bytes()),
        new_public_key: new_key.verifying_key().to_bytes(),
        new_epoch: 3,
        new_schema_digests: v3_trust_schema_digests().unwrap(),
        old_authorization: [0; 64],
        new_proof_of_possession: [0; 64],
    };
    rotation.new_proof_of_possession = new_key
        .sign(&rotation_v3_new_pop_transcript(old, &rotation).unwrap())
        .to_bytes();
    rotation.old_authorization = old_key
        .sign(&rotation_v3_old_authorization_transcript(&rotation).unwrap())
        .to_bytes();
    (
        new_key,
        verify_trust_upgrade_v2_to_v3(old, &rotation).unwrap(),
    )
}

pub fn delegation(role: &str, key: &SigningKey) -> DelegationV1 {
    let (number, schema_id) = match role {
        "RC1_QUALIFICATION_AUTHORIZER" => (1, "runne.release.rc1-qualification-decision/1"),
        "RC2_SIGNING_AUTHORIZER" => (2, "runne.release.rc2-signing-authorization/1"),
        _ => (3, "runne.release.rc3-publication-authorization/1"),
    };
    let public_key = key.verifying_key().to_bytes();
    DelegationV1 {
        role: role.into(),
        principal_id: format!("principal-{number}"),
        controlling_account_id: format!("account-{number}"),
        lane_id: format!("lane-{number}"),
        key_id: hex(&key_id(&public_key)),
        public_key,
        key_epoch: 1,
        signature_profile_id: format!("profile-{number}"),
        not_before: "2026-08-13T00:00:02Z".into(),
        expires_at: "2026-08-13T00:00:04Z".into(),
        revocation_epoch: 1,
        allowed_payload_schema_ids: vec![schema_id.into()],
    }
}

#[allow(dead_code)]
pub fn signed_bootstrap() -> (
    SigningKey,
    VerifiedTrustConfigV3,
    runne_project_owner_authority::VerifiedDocumentReconciliation,
    SignedPromotionBootstrapV4,
) {
    let (v2_key, initial_key, initial_trust, v2) = v2_trust();
    let predecessor = raw_predecessor(&v2, &v2_key, &initial_key, &initial_trust);
    let (root_key, trust) = trust_v3(&v2, &v2_key);
    let keys = [
        SigningKey::from_bytes(&[50; 32]),
        SigningKey::from_bytes(&[51; 32]),
        SigningKey::from_bytes(&[52; 32]),
    ];
    let unsigned = PromotionBootstrapV4 {
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
            "RC1_QUALIFICATION_AUTHORIZER",
            "RC2_SIGNING_AUTHORIZER",
            "RC3_PUBLICATION_AUTHORIZER",
        ]
        .into_iter()
        .zip(keys.iter())
        .map(|(role, key)| delegation(role, key))
        .collect(),
        subject: GitSubject {
            object_format: "sha1".into(),
            commit_oid: "5".repeat(40),
            tree_oid: "6".repeat(40),
        },
        documents: vec![
            Document {
                path: "docs/adr/ADR-0028-promotion-and-release-authority-v2.md".into(),
                mode: "100644".into(),
                blob_oid: "3b7212501922c71abfa3b3fc4dcf6ae879de87bb".into(),
                content_sha256: "a26a9e3e0abe91fd7dd149aa70e69acc98bf7d88a7a16f1a4ecdfad958b447a9"
                    .into(),
                byte_length: 5_974,
                schema_id: None,
            },
            Document {
                path: "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md"
                    .into(),
                mode: "100644".into(),
                blob_oid: "7dc041799a2187633998a5883cac14221feda73b".into(),
                content_sha256: "281599b27a9c578291527ca6e056de9369073e006687dd1149420d83a2cc86b9"
                    .into(),
                byte_length: 26_202,
                schema_id: None,
            },
        ],
        trust_config_sha256: String::new(),
        key_id: String::new(),
        key_epoch: 0,
    };
    let signed = sign_promotion_bootstrap_v3(
        &trust,
        &predecessor,
        unsigned,
        &TestSigner(root_key.clone()),
    )
    .unwrap();
    (root_key, trust, predecessor, signed)
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes
        .iter()
        .flat_map(|byte| [nibble(byte >> 4), nibble(byte & 0x0f)])
        .collect()
}

const fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}
