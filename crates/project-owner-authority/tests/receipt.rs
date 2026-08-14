use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use gocode_project_owner_authority::{
    AuthorityError, DocumentBinding, GitSubject, ProjectOwnerTrustConfigV1, PurposeProfileV1,
    SignedReceipt, Signer, TrustAnchorState, canonical_checked_in_receipt,
    canonical_genesis_without_pop, framed_transcript, key_id, sign_receipt,
    v1_platform_scope_schema_digests, verify_receipt_bytes,
};
use sha2::{Digest, Sha256};

const POP_DOMAIN: &[u8] = b"gocode.project-owner.genesis-pop/1";

struct TestSigner(SigningKey);

impl Signer for TestSigner {
    fn sign(&self, transcript: &[u8]) -> Result<[u8; 64], AuthorityError> {
        Ok(self.0.sign(transcript).to_bytes())
    }
}

fn config(signing: &SigningKey) -> ProjectOwnerTrustConfigV1 {
    let mut config = ProjectOwnerTrustConfigV1 {
        schema_version: "gocode.project-owner.trust-config/1".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 1,
        key_id: key_id(&signing.verifying_key().to_bytes()),
        public_key: signing.verifying_key().to_bytes(),
        schema_digests: v1_platform_scope_schema_digests(),
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
    TrustAnchorState::confirmed("gocode".into(), 1, config.sha256().expect("config sha"))
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
        DocumentBinding {
            path: "docs/decisions/v1-platform-scope-v1.json".into(),
            mode: "100644".into(),
            blob_oid: "7".repeat(40),
            content_sha256: "8".repeat(64),
            byte_length: 512,
            schema_id: Some("gocode.governance.v1-platform-scope-decision/1".into()),
        },
        DocumentBinding {
            path: "docs/adr/ADR-0027-v1-platform-scope.md".into(),
            mode: "100644".into(),
            blob_oid: "5".repeat(40),
            content_sha256: "6".repeat(64),
            byte_length: 1024,
            schema_id: None,
        },
    ]
}

fn signed() -> (SignedReceipt, ProjectOwnerTrustConfigV1, TrustAnchorState) {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let config = config(&signing);
    let receipt = sign_receipt(
        &PurposeProfileV1::v1_platform_scope(),
        &config,
        &anchor(&config),
        subject(),
        documents(),
        "2026-08-12T00:00:00Z".into(),
        &TestSigner(signing),
    )
    .expect("sign exact receipt");
    let anchor = anchor(&config);
    (receipt, config, anchor)
}

fn verify_signed(
    receipt: &SignedReceipt,
    trust: &ProjectOwnerTrustConfigV1,
    anchor: &TrustAnchorState,
) -> Result<(), AuthorityError> {
    let bytes = canonical_checked_in_receipt(&receipt.unsigned, &receipt.signature)?;
    verify_receipt_bytes(
        &bytes,
        receipt.project_owner_authority_receipt_sha256,
        &PurposeProfileV1::v1_platform_scope(),
        trust,
        anchor,
    )
}

#[test]
fn signs_reordered_exact_documents_and_hashes_final_lf_bytes() {
    let (receipt, config, anchor) = signed();
    verify_signed(&receipt, &config, &anchor).expect("verify receipt");
    let canonical = canonical_checked_in_receipt(&receipt.unsigned, &receipt.signature)
        .expect("canonical checked-in receipt");
    assert_eq!(canonical.last(), Some(&b'\n'));
    assert!(
        canonical
            .windows(13)
            .any(|part| part == b"\"signature\":\"")
    );
    assert!(!canonical.contains(&b'='));
    let expected: [u8; 32] = Sha256::digest(canonical).into();
    assert_eq!(receipt.project_owner_authority_receipt_sha256, expected);
}

#[test]
fn rejects_duplicate_missing_extra_and_unlisted_document_paths() {
    let profile = PurposeProfileV1::v1_platform_scope();
    for documents in [
        vec![documents()[0].clone(), documents()[0].clone()],
        vec![documents()[0].clone()],
        {
            let mut value = documents();
            value.push(DocumentBinding {
                path: "docs/extra.md".into(),
                mode: "100644".into(),
                blob_oid: "a".repeat(40),
                content_sha256: "b".repeat(64),
                byte_length: 1,
                schema_id: None,
            });
            value
        },
    ] {
        assert_eq!(
            profile.validate_documents(&documents),
            Err(AuthorityError::InvalidPurposeProfile)
        );
    }
    let mut wildcard = profile;
    wildcard.required_paths.insert("docs/*.md".into());
    assert_eq!(
        wildcard.validate_documents(&documents()),
        Err(AuthorityError::InvalidPurposeProfile)
    );
}

#[test]
fn rejects_symlink_submodule_and_unsafe_paths_before_signing() {
    let profile = PurposeProfileV1::v1_platform_scope();
    for (path, mode) in [
        ("docs/../secret.md", "100644"),
        ("docs/link", "120000"),
        ("docs/module", "160000"),
    ] {
        let mut value = documents();
        value[0].path = path.into();
        value[0].mode = mode.into();
        assert_eq!(
            profile.validate_documents(&value),
            Err(AuthorityError::InvalidDocumentBinding)
        );
    }
}

#[test]
fn detects_blob_digest_length_and_domain_mutations() {
    let (receipt, trust, anchor) = signed();
    for mutate in [
        |receipt: &mut SignedReceipt| {
            receipt.unsigned.documents[0]
                .blob_oid
                .replace_range(0..1, "a");
        },
        |receipt: &mut SignedReceipt| {
            receipt.unsigned.documents[0]
                .content_sha256
                .replace_range(0..1, "a");
        },
        |receipt: &mut SignedReceipt| receipt.unsigned.documents[0].byte_length += 1,
        |receipt: &mut SignedReceipt| receipt.unsigned.purpose = "OTHER_AUTHORIZATION".into(),
        |receipt: &mut SignedReceipt| receipt.unsigned.role = "OTHER_ROLE".into(),
        |receipt: &mut SignedReceipt| receipt.unsigned.trust_config_sha256 = "a".repeat(64),
        |receipt: &mut SignedReceipt| receipt.signature[0] ^= 1,
        |receipt: &mut SignedReceipt| receipt.project_owner_authority_receipt_sha256[0] ^= 1,
    ] {
        let mut changed = receipt.clone();
        mutate(&mut changed);
        assert!(verify_signed(&changed, &trust, &anchor).is_err());
    }
}

#[test]
fn rejects_wrong_key_or_epoch() {
    let (receipt, trust, anchor) = signed();
    let mut wrong_epoch = receipt.clone();
    wrong_epoch.unsigned.key_epoch = 2;
    assert!(verify_signed(&wrong_epoch, &trust, &anchor).is_err());
    let other = config(&SigningKey::from_bytes(&[9; 32]));
    assert!(verify_signed(&receipt, &other, &anchor).is_err());
    assert_eq!(
        sign_receipt(
            &PurposeProfileV1::v1_platform_scope(),
            &trust,
            &anchor,
            subject(),
            documents(),
            "2026-08-12T00:00:00Z".into(),
            &TestSigner(SigningKey::from_bytes(&[9; 32])),
        ),
        Err(AuthorityError::InvalidReceiptSignature)
    );
}

#[test]
fn rejects_document_oid_width_that_differs_from_subject_format() {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let trust = config(&signing);
    let mut bindings = documents();
    bindings[0].blob_oid = "a".repeat(64);
    assert_eq!(
        sign_receipt(
            &PurposeProfileV1::v1_platform_scope(),
            &trust,
            &anchor(&trust),
            subject(),
            bindings,
            "2026-08-12T00:00:00Z".into(),
            &TestSigner(signing),
        ),
        Err(AuthorityError::InvalidDocumentBinding)
    );
}
