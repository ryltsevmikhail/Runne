use ed25519_dalek::{Signer, SigningKey};
use gocode_project_owner_authority::{
    AuthorityError, DocumentBinding, GitSubject, PurposeProfileV1, Signer as ReceiptSigner,
    TrustAnchorState, sign_receipt, verify_rotation,
};

mod rotation_support;
use rotation_support::{genesis, rotation};

struct TestReceiptSigner(SigningKey);

impl ReceiptSigner for TestReceiptSigner {
    fn sign(&self, transcript: &[u8]) -> Result<[u8; 64], AuthorityError> {
        Ok(self.0.sign(transcript).to_bytes())
    }
}

#[test]
fn rotated_successor_can_sign_a_receipt_at_epoch_two() {
    let old = genesis();
    let successor = verify_rotation(&old, &rotation(&old)).expect("successor");
    let anchor = TrustAnchorState::confirmed(
        "gocode".into(),
        2,
        successor.sha256().expect("successor sha"),
    );
    let documents = vec![
        DocumentBinding {
            path: "docs/adr/ADR-0027-v1-platform-scope.md".into(),
            mode: "100644".into(),
            blob_oid: "5".repeat(40),
            content_sha256: "6".repeat(64),
            byte_length: 1024,
            schema_id: None,
        },
        DocumentBinding {
            path: "docs/decisions/v1-platform-scope-v1.json".into(),
            mode: "100644".into(),
            blob_oid: "7".repeat(40),
            content_sha256: "8".repeat(64),
            byte_length: 512,
            schema_id: Some("gocode.governance.v1-platform-scope-decision/1".into()),
        },
    ];
    let result = sign_receipt(
        &PurposeProfileV1::v1_platform_scope(),
        &successor,
        &anchor,
        GitSubject {
            object_format: "sha1".into(),
            commit_oid: "c".repeat(40),
            tree_oid: "d".repeat(40),
        },
        documents,
        "2026-08-12T00:00:00Z".into(),
        &TestReceiptSigner(SigningKey::from_bytes(&[8; 32])),
    );
    assert!(
        result.is_ok(),
        "rotated trust must remain signable: {result:?}"
    );
}
