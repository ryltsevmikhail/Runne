use gocode_project_owner_authority::{
    DelegationV1, PromotionBootstrapV4, RECEIPT_SCHEMA_V4, canonical_unsigned_promotion_bootstrap,
};

fn delegation(role: &str, byte: u8) -> DelegationV1 {
    DelegationV1 {
        role: role.into(),
        principal_id: format!("principal-{byte}"),
        controlling_account_id: format!("account-{byte}"),
        lane_id: format!("lane-{byte}"),
        key_id: "0".repeat(64),
        public_key: [byte; 32],
        key_epoch: 1,
        signature_profile_id: format!("gocode.release.stage-signature/{byte}"),
        not_before: "2026-08-13T00:00:01Z".into(),
        expires_at: "2026-08-13T00:00:03Z".into(),
        revocation_epoch: 1,
        allowed_payload_schema_ids: vec![format!("gocode.release.stage-{byte}/1")],
    }
}

#[test]
fn v4_canonical_bootstrap_has_its_own_schema_and_preserves_delegation_order() {
    let bootstrap = PromotionBootstrapV4 {
        schema_version: RECEIPT_SCHEMA_V4.into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        purpose: "POST_RC0_PROMOTION_AUTHORITY_BOOTSTRAP".into(),
        profile: "gocode.project-owner.post-rc0-promotion/1".into(),
        predecessor_receipt_sha256: [1; 32],
        platform_qualified_subject_sha256: [2; 32],
        platform_matrix_sha256: [3; 32],
        promotion_policy_sha256: [4; 32],
        promotion_policy_revision: "1".into(),
        authority_store_profile: "fixture-only".into(),
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
        subject: gocode_project_owner_authority::GitSubject {
            object_format: "sha1".into(),
            commit_oid: "a".repeat(40),
            tree_oid: "b".repeat(40),
        },
        documents: vec![],
        trust_config_sha256: "c".repeat(64),
        key_id: "d".repeat(64),
        key_epoch: 3,
    };
    let canonical = canonical_unsigned_promotion_bootstrap(&bootstrap).unwrap();
    assert!(canonical.ends_with(b"\n"));
    assert!(
        canonical
            .windows(b"RC1_QUALIFICATION_AUTHORIZER".len())
            .position(|v| v == b"RC1_QUALIFICATION_AUTHORIZER")
            < canonical
                .windows(b"RC2_SIGNING_AUTHORIZER".len())
                .position(|v| v == b"RC2_SIGNING_AUTHORIZER")
    );
}
