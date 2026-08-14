#![allow(clippy::missing_panics_doc, clippy::must_use_candidate)]

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use gocode_project_owner_authority::{
    AuthorityError, DocumentBinding, GitSubject, ProjectOwnerTrustConfigV1, SchemaDigest, Signer,
    TrustAnchorState,
};

pub const PATHS: [&str; 28] = [
    "docs/ROADMAP.md",
    "docs/STATUS.md",
    "docs/adr/ADR-0010-sandbox-enforcement.md",
    "docs/adr/README.md",
    "docs/decisions/DECISION_LOG.md",
    "docs/decisions/OPEN_QUESTIONS.md",
    "docs/desktop/07-testing/CI_AND_PLATFORM_MATRIX.md",
    "docs/desktop/09-release/PLATFORM_SUPPORT.md",
    "docs/desktop/ROADMAP.md",
    "docs/desktop/STATUS.md",
    "docs/desktop/adr/ADR-0012-platform-support-floor.md",
    "docs/desktop/adr/README.md",
    "docs/desktop/decisions/DECISION_LOG.md",
    "docs/desktop/decisions/OPEN_QUESTIONS.md",
    "docs/evidence/PHASE6_SECURITY_PLATFORM_EVIDENCE.md",
    "docs/matrices/REQUIREMENTS_TRACEABILITY.md",
    "docs/matrices/v1-platform-scope-claim-migration-v1.json",
    "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json",
    "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_MANIFEST_V1.md",
    "docs/release/COMPATIBILITY_V1.md",
    "docs/release/POST_RC0_PLATFORM_QUALIFICATION_INTERFACE_V1.md",
    "docs/release/RELEASE_MANIFEST_V1.md",
    "docs/superpowers/specs/2026-07-27-phase6-core-native-qualification-design.md",
    "docs/superpowers/specs/2026-07-27-phase6-security-platform-design.md",
    "docs/superpowers/specs/2026-07-28-phase10-release-qualification-design.md",
    "docs/superpowers/specs/2026-07-31-production-capabilities-program-design.md",
    "docs/superpowers/specs/2026-08-08-rc0-candidate-design.md",
    "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md",
];
pub const INITIAL_FIXTURE: &[u8] = include_bytes!(
    "../../../../scripts/project_owner_authority/fixtures/v3/reconciliation/initial-receipt.json"
);
pub const S2_FIXTURE: &[u8] = include_bytes!(
    "../../../../scripts/project_owner_authority/fixtures/v3/reconciliation/receipt-s2.json"
);

pub struct TestSigner(pub SigningKey);
impl Signer for TestSigner {
    fn sign(&self, transcript: &[u8]) -> Result<[u8; 64], AuthorityError> {
        Ok(self.0.sign(transcript).to_bytes())
    }
}
pub fn trust(key: &SigningKey, schema_digests: Vec<SchemaDigest>) -> ProjectOwnerTrustConfigV1 {
    let mut value = ProjectOwnerTrustConfigV1 {
        schema_version: "gocode.project-owner.trust-config/1".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 1,
        key_id: gocode_project_owner_authority::key_id(&key.verifying_key().to_bytes()),
        public_key: key.verifying_key().to_bytes(),
        schema_digests,
        proof_of_possession: [0; 64],
        predecessor: None,
    };
    let bytes = gocode_project_owner_authority::framed_transcript(
        b"gocode.project-owner.genesis-pop/1",
        &gocode_project_owner_authority::canonical_genesis_without_pop(&value).unwrap(),
    )
    .unwrap();
    value.proof_of_possession = key.sign(&bytes).to_bytes();
    value
}
pub fn anchor(value: &ProjectOwnerTrustConfigV1) -> TrustAnchorState {
    TrustAnchorState::confirmed("gocode".into(), 1, value.sha256().unwrap())
}
pub fn subject(byte: char) -> GitSubject {
    GitSubject {
        object_format: "sha1".into(),
        commit_oid: byte.to_string().repeat(40),
        tree_oid: "d".repeat(40),
    }
}
pub fn binding(path: &str, byte: char) -> DocumentBinding {
    DocumentBinding {
        path: path.into(),
        mode: "100644".into(),
        blob_oid: byte.to_string().repeat(40),
        content_sha256: byte.to_string().repeat(64),
        byte_length: 1,
        schema_id: match path {
            "docs/matrices/v1-platform-scope-claim-migration-v1.json" => {
                Some("gocode.v1-platform-scope-claim-migration/1".into())
            }
            "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json" => {
                Some("gocode.rc0.post-rc0-platform-composed-universe/1".into())
            }
            _ => None,
        },
    }
}
pub fn v2_documents() -> Vec<DocumentBinding> {
    let mut values = vec![
        binding("docs/adr/ADR-0027-v1-platform-scope.md", '1'),
        binding("docs/decisions/v1-platform-scope-v1.json", '2'),
        binding("docs/desktop/adr/ADR-0015-v1-platform-scope.md", '3'),
        binding(
            "docs/schemas/v1-platform-scope-decision-v1.schema.json",
            '4',
        ),
    ];
    values[1].schema_id = Some("gocode.governance.v1-platform-scope-decision/1".into());
    values
}
