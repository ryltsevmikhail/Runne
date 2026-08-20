//! Adversarial raw V4 receipt parser vectors.
use crate::{
    DelegationV1, Document, GitSubject, PromotionBootstrapV4, RECEIPT_SCHEMA_V4,
    canonical_checked_in_promotion_bootstrap, receipt_v4_wire::receipt_from_bytes,
};

fn receipt() -> PromotionBootstrapV4 {
    let delegation = |role: &str, n: u8| DelegationV1 {
        role: role.into(),
        principal_id: format!("principal-{n}"),
        controlling_account_id: format!("account-{n}"),
        lane_id: format!("lane-{n}"),
        key_id: "0".repeat(64),
        public_key: [n; 32],
        key_epoch: 1,
        signature_profile_id: format!("profile-{n}"),
        not_before: "2026-08-13T00:00:01Z".into(),
        expires_at: "2026-08-13T00:00:03Z".into(),
        revocation_epoch: 1,
        allowed_payload_schema_ids: vec![
            match n {
                1 => "gocode.release.rc1-qualification-decision/1",
                2 => "gocode.release.rc2-signing-authorization/1",
                _ => "gocode.release.rc3-publication-authorization/1",
            }
            .into(),
        ],
    };
    PromotionBootstrapV4 {
        schema_version: RECEIPT_SCHEMA_V4.into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        purpose: "POST_RC0_PROMOTION_AUTHORITY_BOOTSTRAP".into(),
        profile: "gocode.project-owner.post-rc0-promotion/1".into(),
        predecessor_receipt_sha256: [1; 32],
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
        delegations: vec![
            delegation("RC1_QUALIFICATION_AUTHORIZER", 1),
            delegation("RC2_SIGNING_AUTHORIZER", 2),
            delegation("RC3_PUBLICATION_AUTHORIZER", 3),
        ],
        subject: GitSubject {
            object_format: "sha1".into(),
            commit_oid: "5".repeat(40),
            tree_oid: "6".repeat(40),
        },
        documents: [
            "docs/adr/ADR-0028-promotion-and-release-authority-v2.md",
            "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md",
        ]
        .into_iter()
        .map(|path| Document {
            path: path.into(),
            mode: "100644".into(),
            blob_oid: "7".repeat(40),
            content_sha256: "8".repeat(64),
            byte_length: 1,
            schema_id: None,
        })
        .collect(),
        trust_config_sha256: "9".repeat(64),
        key_id: "a".repeat(64),
        key_epoch: 3,
    }
}

#[test]
fn raw_v4_parser_rejects_crlf_missing_lf_duplicate_and_unknown_fields() {
    let bytes = canonical_checked_in_promotion_bootstrap(&receipt(), &[0; 64]).unwrap();
    assert!(receipt_from_bytes(&bytes).is_ok());
    let crlf = String::from_utf8(bytes.clone())
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();
    assert_eq!(
        receipt_from_bytes(&crlf),
        Err(crate::AuthorityError::InvalidCanonicalReceipt)
    );
    assert_eq!(
        receipt_from_bytes(&bytes[..bytes.len() - 1]),
        Err(crate::AuthorityError::InvalidCanonicalReceipt)
    );
    let duplicate = String::from_utf8(bytes.clone())
        .unwrap()
        .replacen('{', "{\"authority_store_profile\":\"x\",", 1)
        .into_bytes();
    assert!(receipt_from_bytes(&duplicate).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), serde_json::Value::Null);
    let mut unknown = serde_json::to_vec(&value).unwrap();
    unknown.push(b'\n');
    assert_eq!(
        receipt_from_bytes(&unknown),
        Err(crate::AuthorityError::InvalidReceipt)
    );
    let mut malformed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    malformed["signature"] = serde_json::Value::String("A".into());
    let mut malformed = serde_json::to_vec(&malformed).unwrap();
    malformed.push(b'\n');
    assert_eq!(
        receipt_from_bytes(&malformed),
        Err(crate::AuthorityError::InvalidReceiptSignature)
    );
}
