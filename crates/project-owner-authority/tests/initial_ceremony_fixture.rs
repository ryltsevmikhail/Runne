use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use gocode_project_owner_authority::{
    AuthorityError, DocumentBinding, GitSubject, ProjectOwnerTrustConfigV1, PurposeProfileV2,
    SchemaDigest, Signer, TrustAnchorState, canonical_checked_in_receipt,
    canonical_genesis_without_pop, framed_transcript, key_id, sign_receipt_v2,
    v2_platform_scope_schema_digests, verify_receipt_v2_bytes,
};
use sha2::{Digest, Sha256};

const POP_DOMAIN: &[u8] = b"gocode.project-owner.genesis-pop/1";
const RECEIPT: &[u8] = include_bytes!(
    "../../../scripts/project_owner_authority/fixtures/v2/initial-ceremony/receipt-s.json"
);

struct FixtureSigner(SigningKey);

impl Signer for FixtureSigner {
    fn sign(&self, transcript: &[u8]) -> Result<[u8; 64], AuthorityError> {
        Ok(self.0.sign(transcript).to_bytes())
    }
}

fn trust(signing: &SigningKey) -> ProjectOwnerTrustConfigV1 {
    let mut trust = ProjectOwnerTrustConfigV1 {
        schema_version: "gocode.project-owner.trust-config/1".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 1,
        key_id: key_id(&signing.verifying_key().to_bytes()),
        public_key: signing.verifying_key().to_bytes(),
        schema_digests: v2_platform_scope_schema_digests(),
        proof_of_possession: [0; 64],
        predecessor: None,
    };
    let pop = framed_transcript(
        POP_DOMAIN,
        &canonical_genesis_without_pop(&trust).expect("canonical trust"),
    )
    .expect("framed proof");
    trust.proof_of_possession = signing.sign(&pop).to_bytes();
    trust
}

fn bindings() -> Vec<DocumentBinding> {
    vec![
        binding(
            "docs/adr/ADR-0027-v1-platform-scope.md",
            "0e7139b0e91844abea692d84bb695fe95d58ebcd",
            "7a4a102e916b7c96fa44e48580082d6133cc9338f001a112003ff04a5218d208",
            67,
            None,
        ),
        binding(
            "docs/decisions/v1-platform-scope-v1.json",
            "8ad2ede86bf64176e438a8fd1076f3b4505a80e3",
            "2ba3f59d56214103bb69560015a0c1fc971bd8dd0725b141d44b9a74d6846bd7",
            83,
            Some("gocode.governance.v1-platform-scope-decision/1"),
        ),
        binding(
            "docs/desktop/adr/ADR-0015-v1-platform-scope.md",
            "8196539f2617cd0346ce82ef82b7347f6ca60f9f",
            "497dec97dff7a5ba3475a999f2e355d27605207a3786fefbcf8ea6bee88a791a",
            67,
            None,
        ),
        binding(
            "docs/schemas/v1-platform-scope-decision-v1.schema.json",
            "4558997feb8baed9c5554ea703d0f7804eb2abbf",
            "0ae86b8b1bec5fba66cb7675e8c074b224762e31ce161a635d9cdd069c3304f8",
            72,
            None,
        ),
    ]
}

fn binding(
    path: &str,
    blob_oid: &str,
    content_sha256: &str,
    byte_length: u64,
    schema_id: Option<&str>,
) -> DocumentBinding {
    DocumentBinding {
        path: path.into(),
        mode: "100644".into(),
        blob_oid: blob_oid.into(),
        content_sha256: content_sha256.into(),
        byte_length,
        schema_id: schema_id.map(str::to_owned),
    }
}

#[test]
fn checked_in_initial_ceremony_receipt_is_real_canonical_v2_bytes() {
    let signing = SigningKey::from_bytes(&[13; 32]);
    let trust = trust(&signing);
    let anchor =
        TrustAnchorState::confirmed("gocode".into(), 1, trust.sha256().expect("trust hash"));
    let receipt = sign_receipt_v2(
        &PurposeProfileV2::v1_platform_scope(),
        &trust,
        &anchor,
        GitSubject {
            object_format: "sha1".into(),
            commit_oid: "50b4ae093e8b60693396482caf5c938627da8aa8".into(),
            tree_oid: "4124d9d59965b6ade10a024635e2cba2ba616130".into(),
        },
        bindings(),
        "2026-08-13T00:00:00Z".into(),
        &FixtureSigner(signing),
    )
    .expect("fixture receipt");
    let canonical = canonical_checked_in_receipt(&receipt.unsigned, &receipt.signature)
        .expect("canonical receipt");
    assert_eq!(
        RECEIPT,
        canonical.as_slice(),
        "expected fixture:\n{}",
        String::from_utf8_lossy(&canonical)
    );
    verify_receipt_v2_bytes(
        RECEIPT,
        Sha256::digest(RECEIPT).into(),
        &PurposeProfileV2::v1_platform_scope(),
        &trust,
        &anchor,
    )
    .expect("public raw-byte verification");
}

#[test]
fn v2_reviewed_pins_are_not_extensible_by_callers() {
    let mut pins = v2_platform_scope_schema_digests();
    pins.push(SchemaDigest {
        schema_id: "gocode.unreviewed/2".into(),
        schema_sha256: [0; 32],
    });
    assert_eq!(
        PurposeProfileV2::with_reviewed_schema_digests(pins),
        Err(AuthorityError::InvalidPurposeProfile)
    );
}
