//! Narrow test-only inputs for the raw promotion authority chain.

pub mod chain;

use std::cell::Cell;

use ed25519_dalek::{Signer as _, SigningKey};
use runne_project_owner_authority::{
    AuthorityError, DocumentBinding, GitSubject, ProjectOwnerTrustConfigV1,
    PromotionBootstrapAdmission, PromotionBootstrapAdmissionScope, PromotionBootstrapValidity,
    PromotionBootstrapVerificationContext, PromotionBootstrapVerificationState, SchemaDigest,
    Signer, TrustAnchorState, canonical_genesis_without_pop, framed_transcript, key_id,
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

pub struct TestSigner(pub SigningKey);
impl Signer for TestSigner {
    fn sign(&self, transcript: &[u8]) -> Result<[u8; 64], AuthorityError> {
        Ok(self.0.sign(transcript).to_bytes())
    }
}

#[allow(
    dead_code,
    reason = "shared by only the raw bootstrap call-site integration tests"
)]
pub struct BootstrapContext {
    admitted: Cell<Option<[u8; 32]>>,
}
#[allow(
    dead_code,
    reason = "shared by only the raw bootstrap call-site integration tests"
)]
impl BootstrapContext {
    pub const fn valid() -> Self {
        Self {
            admitted: Cell::new(None),
        }
    }
}
impl PromotionBootstrapVerificationContext for BootstrapContext {
    fn authority_store_profile(&self) -> Result<&str, AuthorityError> {
        Ok("store-1")
    }
    fn read_state(&self) -> Result<PromotionBootstrapVerificationState, AuthorityError> {
        Ok(PromotionBootstrapVerificationState {
            revocation_epoch: 1,
            generation: 7,
        })
    }
    fn admit_or_recover_bootstrap(
        &self,
        expected: &PromotionBootstrapVerificationState,
        digest: [u8; 32],
        scope: &PromotionBootstrapAdmissionScope,
        validity: &PromotionBootstrapValidity,
    ) -> Result<PromotionBootstrapAdmission, AuthorityError> {
        if let Some(admitted) = self.admitted.get() {
            return if admitted == digest {
                if expected.revocation_epoch == scope.root_revocation_epoch() {
                    Ok(PromotionBootstrapAdmission::ExistingSame)
                } else {
                    Err(AuthorityError::StaleOrRevokedPromotionBootstrap)
                }
            } else {
                Err(AuthorityError::PromotionBootstrapAdmissionConflict)
            };
        }
        if expected.generation != 7
            || expected.revocation_epoch != scope.root_revocation_epoch()
            || validity.issued_at() > "2026-08-13T00:00:03Z"
            || validity.not_before() > "2026-08-13T00:00:03Z"
            || validity.expires_at() <= "2026-08-13T00:00:03Z"
        {
            return Err(AuthorityError::StaleOrRevokedPromotionBootstrap);
        }
        self.admitted.set(Some(digest));
        Ok(PromotionBootstrapAdmission::NewlyAdmitted)
    }
}

pub fn trust(key: &SigningKey, schema_digests: Vec<SchemaDigest>) -> ProjectOwnerTrustConfigV1 {
    let mut trust = ProjectOwnerTrustConfigV1 {
        schema_version: "runne.project-owner.trust-config/1".into(),
        repository_id: "runne".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 1,
        key_id: key_id(&key.verifying_key().to_bytes()),
        public_key: key.verifying_key().to_bytes(),
        schema_digests,
        proof_of_possession: [0; 64],
        predecessor: None,
    };
    trust.proof_of_possession = key
        .sign(
            &framed_transcript(
                b"runne.project-owner.genesis-pop/1",
                &canonical_genesis_without_pop(&trust).unwrap(),
            )
            .unwrap(),
        )
        .to_bytes();
    trust
}

pub fn anchor(trust: &ProjectOwnerTrustConfigV1) -> TrustAnchorState {
    TrustAnchorState::confirmed("runne".into(), 1, trust.sha256().unwrap())
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
                Some("runne.v1-platform-scope-claim-migration/1".into())
            }
            "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json" => {
                Some("runne.rc0.post-rc0-platform-composed-universe/1".into())
            }
            _ => None,
        },
    }
}

pub fn v2_documents() -> Vec<DocumentBinding> {
    let mut documents = vec![
        binding("docs/adr/ADR-0027-v1-platform-scope.md", '1'),
        binding("docs/decisions/v1-platform-scope-v1.json", '2'),
        binding("docs/desktop/adr/ADR-0015-v1-platform-scope.md", '3'),
        binding(
            "docs/schemas/v1-platform-scope-decision-v1.schema.json",
            '4',
        ),
    ];
    documents[1].schema_id = Some("runne.governance.v1-platform-scope-decision/1".into());
    documents
}
