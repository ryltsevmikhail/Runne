use ed25519_dalek::SigningKey;
use gocode_project_owner_authority::{
    AuthorityError, PurposeProfileV2, PurposeProfileV3, SchemaDigest, canonical_checked_in_receipt,
    canonical_checked_in_receipt_v3, sign_receipt_v2, sign_receipt_v3,
    v2_platform_scope_schema_digests, verify_initial_authorization_v2_bytes,
    verify_receipt_v3_fixture_bytes,
};
use sha2::Digest;
mod receipt_v3_support;
use receipt_v3_support::{
    INITIAL_FIXTURE, PATHS, S2_FIXTURE, TestSigner, anchor, binding, subject, trust, v2_documents,
};

#[test]
fn v3_binds_the_closed_reconciliation_profile_after_verified_initial_receipt() {
    let key = SigningKey::from_bytes(&[13; 32]);
    let initial_trust = trust(&key, v2_platform_scope_schema_digests());
    let initial = sign_receipt_v2(
        &PurposeProfileV2::v1_platform_scope(),
        &initial_trust,
        &anchor(&initial_trust),
        subject('a'),
        v2_documents(),
        "2026-08-13T00:00:00Z".into(),
        &TestSigner(key.clone()),
    )
    .unwrap();
    let initial_bytes =
        canonical_checked_in_receipt(&initial.unsigned, &initial.signature).unwrap();
    let verified = verify_initial_authorization_v2_bytes(
        &initial_bytes,
        initial.project_owner_authority_receipt_sha256,
        &initial_trust,
        &anchor(&initial_trust),
    )
    .unwrap();
    let v3_trust = trust(
        &key,
        gocode_project_owner_authority::v3_reconciliation_schema_digests(),
    );
    let receipt = sign_receipt_v3(
        &PurposeProfileV3::post_rc0_document_reconciliation(),
        &v3_trust,
        &anchor(&v3_trust),
        &verified,
        subject('b'),
        PATHS
            .iter()
            .enumerate()
            .map(|(index, path)| binding(path, char::from(b"123456"[index % 6])))
            .collect(),
        "2026-08-13T00:00:01Z".into(),
        &TestSigner(key),
    )
    .unwrap();
    let bytes = canonical_checked_in_receipt_v3(&receipt.unsigned, &receipt.signature).unwrap();
    let verified_receipt = verify_receipt_v3_fixture_bytes(
        &bytes,
        receipt.project_owner_authority_receipt_sha256,
        &PurposeProfileV3::post_rc0_document_reconciliation(),
        &v3_trust,
        &anchor(&v3_trust),
        &verified,
    )
    .unwrap();
    assert_eq!(
        verified_receipt.receipt_sha256(),
        receipt.project_owner_authority_receipt_sha256
    );
    let mut wrong_digest = receipt.project_owner_authority_receipt_sha256;
    wrong_digest[0] ^= 1;
    assert_eq!(
        verify_receipt_v3_fixture_bytes(
            &bytes,
            wrong_digest,
            &PurposeProfileV3::post_rc0_document_reconciliation(),
            &v3_trust,
            &anchor(&v3_trust),
            &verified,
        ),
        Err(AuthorityError::InvalidReceiptDigest)
    );
    let mut noncanonical = bytes;
    noncanonical.pop();
    assert_eq!(
        verify_receipt_v3_fixture_bytes(
            &noncanonical,
            sha2::Sha256::digest(&noncanonical).into(),
            &PurposeProfileV3::post_rc0_document_reconciliation(),
            &v3_trust,
            &anchor(&v3_trust),
            &verified,
        ),
        Err(AuthorityError::InvalidCanonicalReceipt)
    );
    assert_eq!(
        receipt.predecessor_receipt_sha256,
        initial.project_owner_authority_receipt_sha256
    );
    let mut missing = receipt;
    missing.predecessor_receipt_sha256 = [0; 32];
    missing.unsigned.predecessor_receipt_sha256 = [0; 32];
    assert!(
        verify_receipt_v3_fixture_bytes(
            &canonical_checked_in_receipt_v3(&missing.unsigned, &missing.signature).unwrap(),
            missing.project_owner_authority_receipt_sha256,
            &PurposeProfileV3::post_rc0_document_reconciliation(),
            &v3_trust,
            &anchor(&v3_trust),
            &verified,
        )
        .is_err()
    );
}

#[test]
fn v3_rejects_missing_extra_self_and_post_signature_binding_mutations() {
    let key = SigningKey::from_bytes(&[23; 32]);
    let initial_trust = trust(&key, v2_platform_scope_schema_digests());
    let initial = sign_receipt_v2(
        &PurposeProfileV2::v1_platform_scope(),
        &initial_trust,
        &anchor(&initial_trust),
        subject('a'),
        v2_documents(),
        "2026-08-13T00:00:00Z".into(),
        &TestSigner(key.clone()),
    )
    .unwrap();
    let initial_bytes =
        canonical_checked_in_receipt(&initial.unsigned, &initial.signature).unwrap();
    let verified = verify_initial_authorization_v2_bytes(
        &initial_bytes,
        initial.project_owner_authority_receipt_sha256,
        &initial_trust,
        &anchor(&initial_trust),
    )
    .unwrap();
    let v3_trust = trust(
        &key,
        gocode_project_owner_authority::v3_reconciliation_schema_digests(),
    );
    let profile = PurposeProfileV3::post_rc0_document_reconciliation();
    let receipt = sign_receipt_v3(
        &profile,
        &v3_trust,
        &anchor(&v3_trust),
        &verified,
        subject('b'),
        PATHS
            .iter()
            .enumerate()
            .map(|(index, path)| binding(path, b"123456"[index % 6].into()))
            .collect(),
        "2026-08-13T00:00:01Z".into(),
        &TestSigner(key),
    )
    .unwrap();
    let mutations: [fn(&mut gocode_project_owner_authority::SignedReceiptV3); 9] = [
        |value| {
            value.unsigned.documents.pop();
        },
        |value| {
            value
                .unsigned
                .documents
                .push(value.unsigned.documents[0].clone());
        },
        |value| {
            value.unsigned.documents[0].path =
                "docs/evidence/reconciliation-receipt-v3.json".into();
        },
        |value| {
            value.unsigned.documents[0].content_sha256 = "f".repeat(64);
        },
        |value| {
            value.unsigned.documents[0].blob_oid = "f".repeat(40);
        },
        |value| {
            value.unsigned.documents[0].byte_length = 2;
        },
        |value| {
            value.unsigned.documents[0].mode = "100755".into();
        },
        |value| {
            value.unsigned.documents[16].schema_id = None;
        },
        |value| {
            value.unsigned.documents.reverse();
        },
    ];
    for mutate in mutations {
        let mut changed = receipt.clone();
        mutate(&mut changed);
        assert!(
            verify_receipt_v3_fixture_bytes(
                &canonical_checked_in_receipt_v3(&changed.unsigned, &changed.signature).unwrap(),
                changed.project_owner_authority_receipt_sha256,
                &profile,
                &v3_trust,
                &anchor(&v3_trust),
                &verified
            )
            .is_err()
        );
    }
}

#[test]
fn v3_rejects_current_v2_pins_and_a_missing_predecessor_hash() {
    let key = SigningKey::from_bytes(&[22; 32]);
    let v2_trust = trust(&key, v2_platform_scope_schema_digests());
    assert_eq!(
        PurposeProfileV3::post_rc0_document_reconciliation().validate_trust(&v2_trust),
        Err(AuthorityError::InvalidSchemaDigests)
    );
    let mut pins = gocode_project_owner_authority::v3_reconciliation_schema_digests();
    pins.push(SchemaDigest {
        schema_id: "gocode.unreviewed/3".into(),
        schema_sha256: [0; 32],
    });
    assert_eq!(
        PurposeProfileV3::with_reviewed_schema_digests(pins),
        Err(AuthorityError::InvalidPurposeProfile)
    );
}

#[test]
fn v3_fixture_receipt_is_strictly_verified_from_canonical_initial_bytes() {
    let key = SigningKey::from_bytes(&[13; 32]);
    let initial_trust = trust(&key, v2_platform_scope_schema_digests());
    let initial_anchor = anchor(&initial_trust);
    let predecessor = verify_initial_authorization_v2_bytes(
        INITIAL_FIXTURE,
        sha2::Sha256::digest(INITIAL_FIXTURE).into(),
        &initial_trust,
        &initial_anchor,
    )
    .unwrap();
    let reconciliation_trust = trust(
        &key,
        gocode_project_owner_authority::v3_reconciliation_schema_digests(),
    );
    let reconciliation_anchor = anchor(&reconciliation_trust);
    verify_receipt_v3_fixture_bytes(
        S2_FIXTURE,
        sha2::Sha256::digest(S2_FIXTURE).into(),
        &PurposeProfileV3::post_rc0_document_reconciliation(),
        &reconciliation_trust,
        &reconciliation_anchor,
        &predecessor,
    )
    .unwrap();
}
