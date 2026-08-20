use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use runne_project_owner_authority::{
    AuthorityError, DocumentBinding, GitSubject, ProjectOwnerTrustConfigV1, PurposeProfileV1,
    SchemaDigest, SignedReceipt, Signer, TrustAnchorState, canonical_genesis_without_pop,
    framed_transcript, key_id, sign_receipt, v1_platform_scope_schema_digests,
};

const POP_DOMAIN: &[u8] = b"gocode.project-owner.genesis-pop/1";

pub struct TestSigner(SigningKey);

impl Signer for TestSigner {
    fn sign(&self, transcript: &[u8]) -> Result<[u8; 64], AuthorityError> {
        Ok(self.0.sign(transcript).to_bytes())
    }
}

#[allow(dead_code)]
#[must_use]
/// Build a valid signed receipt for integration vectors.
///
/// # Panics
///
/// Panics only when the test fixture becomes internally invalid.
pub fn signed() -> (SignedReceipt, ProjectOwnerTrustConfigV1, TrustAnchorState) {
    signed_with_schema_digests(schema_digests()).expect("signed receipt")
}

/// Build a fixture with caller-supplied schema digests.
///
/// # Errors
///
/// Returns the protocol error produced by signing with those digests.
pub fn signed_with_schema_digests(
    schema_digests: Vec<SchemaDigest>,
) -> Result<(SignedReceipt, ProjectOwnerTrustConfigV1, TrustAnchorState), AuthorityError> {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let mut trust = ProjectOwnerTrustConfigV1 {
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
        &canonical_genesis_without_pop(&trust).map_err(|_| AuthorityError::InvalidGenesis)?,
    )
    .map_err(|_| AuthorityError::InvalidGenesis)?;
    trust.proof_of_possession = signing.sign(&message).to_bytes();
    let anchor = TrustAnchorState::confirmed(
        "gocode".into(),
        1,
        trust.sha256().map_err(|_| AuthorityError::InvalidGenesis)?,
    );
    let receipt = sign_receipt(
        &PurposeProfileV1::v1_platform_scope(),
        &trust,
        &anchor,
        subject(),
        documents(),
        "2026-08-12T00:00:00Z".into(),
        &TestSigner(signing),
    )?;
    Ok((receipt, trust, anchor))
}

/// Return the exact supported trust schema-digest allowlist for receipt tests.
#[must_use]
pub fn schema_digests() -> Vec<SchemaDigest> {
    v1_platform_scope_schema_digests()
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
        content_sha256: if blob == "7" { "8" } else { "6" }.repeat(64),
        byte_length: if blob == "7" { 512 } else { 1024 },
        schema_id: schema_id.map(str::to_owned),
    }
}
