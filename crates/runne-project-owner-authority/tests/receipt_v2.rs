use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use runne_project_owner_authority::{
    AuthorityError, DocumentBinding, GitSubject, ProjectOwnerTrustConfigV1, PurposeProfileV1,
    PurposeProfileV2, SchemaDigest, Signer, TrustAnchorState, canonical_checked_in_receipt,
    canonical_genesis_without_pop, framed_transcript, key_id, sign_receipt, sign_receipt_v2,
    v2_platform_scope_schema_digests, verify_receipt_bytes, verify_receipt_v2,
    verify_receipt_v2_bytes,
};
use sha2::{Digest, Sha256};

const POP_DOMAIN: &[u8] = b"gocode.project-owner.genesis-pop/1";

struct TestSigner(SigningKey);

impl Signer for TestSigner {
    fn sign(&self, transcript: &[u8]) -> Result<[u8; 64], AuthorityError> {
        Ok(self.0.sign(transcript).to_bytes())
    }
}

fn config(signing: &SigningKey, schema_digests: Vec<SchemaDigest>) -> ProjectOwnerTrustConfigV1 {
    let mut config = ProjectOwnerTrustConfigV1 {
        schema_version: "gocode.project-owner.trust-config/1".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 1,
        key_id: key_id(&signing.verifying_key().to_bytes()),
        public_key: signing.verifying_key().to_bytes(),
        schema_digests,
        proof_of_possession: [0; 64],
        predecessor: None,
    };
    let message = framed_transcript(
        POP_DOMAIN,
        &canonical_genesis_without_pop(&config).expect("canonical config"),
    )
    .expect("framed config");
    config.proof_of_possession = signing.sign(&message).to_bytes();
    config
}

fn anchor(config: &ProjectOwnerTrustConfigV1) -> TrustAnchorState {
    TrustAnchorState::confirmed("gocode".into(), 1, config.sha256().expect("config digest"))
}

fn subject() -> GitSubject {
    GitSubject {
        object_format: "sha1".into(),
        commit_oid: "c".repeat(40),
        tree_oid: "d".repeat(40),
    }
}

fn documents() -> Vec<DocumentBinding> {
    vec![
        binding(
            "docs/schemas/v1-platform-scope-decision-v1.schema.json",
            "a",
            None,
        ),
        binding("docs/desktop/adr/ADR-0015-v1-platform-scope.md", "9", None),
        binding(
            "docs/decisions/v1-platform-scope-v1.json",
            "7",
            Some("gocode.governance.v1-platform-scope-decision/1"),
        ),
        binding("docs/adr/ADR-0027-v1-platform-scope.md", "5", None),
    ]
}

fn binding(path: &str, blob: &str, schema_id: Option<&str>) -> DocumentBinding {
    DocumentBinding {
        path: path.into(),
        mode: "100644".into(),
        blob_oid: blob.repeat(40),
        content_sha256: (if blob == "7" { "8" } else { blob }).repeat(64),
        byte_length: 1024,
        schema_id: schema_id.map(str::to_owned),
    }
}

fn signed_v2() -> (
    runne_project_owner_authority::SignedReceipt,
    ProjectOwnerTrustConfigV1,
    TrustAnchorState,
) {
    let signing = SigningKey::from_bytes(&[8; 32]);
    let trust = config(&signing, v2_platform_scope_schema_digests());
    let anchor = anchor(&trust);
    let receipt = sign_receipt_v2(
        &PurposeProfileV2::v1_platform_scope(),
        &trust,
        &anchor,
        subject(),
        documents(),
        "2026-08-13T00:00:00Z".into(),
        &TestSigner(signing),
    )
    .expect("sign v2 receipt");
    (receipt, trust, anchor)
}

#[test]
fn v2_signs_the_closed_four_document_profile_and_final_lf_digest() {
    let (receipt, trust, v2_anchor) = signed_v2();
    verify_receipt_v2(
        &receipt,
        &PurposeProfileV2::v1_platform_scope(),
        &trust,
        &v2_anchor,
    )
    .expect("verify v2 receipt");
    let bytes = canonical_checked_in_receipt(&receipt.unsigned, &receipt.signature).expect("bytes");
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert_eq!(
        receipt.project_owner_authority_receipt_sha256,
        Sha256::digest(&bytes).as_slice()
    );
    let paths = receipt
        .unsigned
        .documents
        .iter()
        .map(|document| document.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            "docs/adr/ADR-0027-v1-platform-scope.md",
            "docs/decisions/v1-platform-scope-v1.json",
            "docs/desktop/adr/ADR-0015-v1-platform-scope.md",
            "docs/schemas/v1-platform-scope-decision-v1.schema.json",
        ]
    );
}

#[test]
fn v2_rejects_a_missing_desktop_document() {
    let mut bindings = documents();
    bindings.retain(|item| item.path != "docs/desktop/adr/ADR-0015-v1-platform-scope.md");
    assert_eq!(
        PurposeProfileV2::v1_platform_scope().validate_documents(&bindings),
        Err(AuthorityError::InvalidPurposeProfile)
    );
}

#[test]
fn v2_rejects_a_mutated_profile_that_drops_the_desktop_document() {
    let mut profile = PurposeProfileV2::v1_platform_scope();
    profile
        .required_paths
        .remove("docs/desktop/adr/ADR-0015-v1-platform-scope.md");
    let mut bindings = documents();
    bindings.retain(|item| item.path != "docs/desktop/adr/ADR-0015-v1-platform-scope.md");
    assert_eq!(
        profile.validate_documents(&bindings),
        Err(AuthorityError::InvalidPurposeProfile)
    );
}

#[test]
fn v2_rejects_an_unreviewed_extra_schema_pin() {
    let mut pins = v2_platform_scope_schema_digests();
    pins.push(SchemaDigest {
        schema_id: "gocode.project-owner.unreviewed/2".into(),
        schema_sha256: [0; 32],
    });
    assert_eq!(
        PurposeProfileV2::with_reviewed_schema_digests(pins),
        Err(AuthorityError::InvalidPurposeProfile)
    );
}

#[test]
fn v1_and_v2_entrypoints_reject_each_others_receipts() {
    let (receipt, trust, v2_anchor) = signed_v2();
    let bytes = canonical_checked_in_receipt(&receipt.unsigned, &receipt.signature).expect("bytes");
    assert!(
        verify_receipt_bytes(
            &bytes,
            receipt.project_owner_authority_receipt_sha256,
            &PurposeProfileV1::v1_platform_scope(),
            &trust,
            &v2_anchor,
        )
        .is_err()
    );

    let signing = SigningKey::from_bytes(&[7; 32]);
    let v1_trust = config(
        &signing,
        runne_project_owner_authority::v1_platform_scope_schema_digests(),
    );
    let v1_anchor = anchor(&v1_trust);
    let v1 = sign_receipt(
        &PurposeProfileV1::v1_platform_scope(),
        &v1_trust,
        &v1_anchor,
        subject(),
        vec![documents()[3].clone(), documents()[2].clone()],
        "2026-08-13T00:00:00Z".into(),
        &TestSigner(signing),
    )
    .expect("sign v1 receipt");
    assert!(
        verify_receipt_v2(
            &v1,
            &PurposeProfileV2::v1_platform_scope(),
            &v1_trust,
            &v1_anchor,
        )
        .is_err()
    );
}

#[test]
fn v2_rejects_profile_schema_domain_and_raw_byte_mutations() {
    let (receipt, trust, anchor) = signed_v2();
    for mutate in [
        |receipt: &mut runne_project_owner_authority::SignedReceipt| {
            receipt.unsigned.profile = "gocode.project-owner.v1-platform-scope/1".into();
        },
        |receipt: &mut runne_project_owner_authority::SignedReceipt| {
            receipt.unsigned.schema_version = "gocode.project-owner.authority-receipt/1".into();
        },
        |receipt: &mut runne_project_owner_authority::SignedReceipt| {
            receipt.unsigned.purpose = "OTHER_AUTHORIZATION".into();
        },
    ] {
        let mut changed = receipt.clone();
        mutate(&mut changed);
        assert!(
            verify_receipt_v2(
                &changed,
                &PurposeProfileV2::v1_platform_scope(),
                &trust,
                &anchor,
            )
            .is_err()
        );
    }
    let bytes = canonical_checked_in_receipt(&receipt.unsigned, &receipt.signature).expect("bytes");
    let without_lf = bytes[..bytes.len() - 1].to_vec();
    assert_eq!(
        verify_receipt_v2_bytes(
            &without_lf,
            Sha256::digest(&without_lf).into(),
            &PurposeProfileV2::v1_platform_scope(),
            &trust,
            &anchor,
        ),
        Err(AuthorityError::InvalidCanonicalReceipt)
    );
    let mut wrong_digest = receipt.project_owner_authority_receipt_sha256;
    wrong_digest[0] ^= 1;
    assert_eq!(
        verify_receipt_v2_bytes(
            &bytes,
            wrong_digest,
            &PurposeProfileV2::v1_platform_scope(),
            &trust,
            &anchor,
        ),
        Err(AuthorityError::InvalidReceiptDigest)
    );
}
