#![cfg(feature = "fixture-only")]
#![allow(dead_code)] // Shared support is both a module and an integration-test target.
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    reason = "fixture support exposes ergonomic test constructors"
)]

//! Test-only construction of release inputs from owner-verified raw envelopes.
use ed25519_dalek::{Signer as _, SigningKey};
use runne_project_owner_authority::{
    STAGE_ENVELOPE_SCHEMA_V1, SigningDomain, StageAuthorityEnvelopeV1,
    canonical_checked_in_promotion_bootstrap, canonical_checked_in_stage_envelope,
    canonical_stage_payload, signing_transcript, v3_trust_schema_digests,
    verify_promotion_bootstrap_bytes,
};
use runne_release_authority::{
    CanonicalPayloadKind, CommandId, PromotionId, RawStageTransitionRequest, StageTransitionStore,
};
use sha2::{Digest as _, Sha256};
#[path = "../../runne-project-owner-authority/tests/raw_promotion_support/mod.rs"]
mod owner_support;
use owner_support::BootstrapContext;
use owner_support::chain::{delegation, signed_bootstrap};

#[path = "verified_stage_support/durable_stage_wire.rs"]
pub mod durable_stage_wire;
#[path = "verified_stage_support/verified_stage_payload.rs"]
mod verified_stage_payload;
#[must_use]
pub fn verified_stages(payloads: &[(CanonicalPayloadKind, Vec<u8>)]) -> [FixtureStage; 3] {
    verified_stages_with_first_key(payloads, 50)
}

#[must_use]
pub fn verified_stages_with_first_key(
    payloads: &[(CanonicalPayloadKind, Vec<u8>)],
    first_key: u8,
) -> [FixtureStage; 3] {
    [
        FixtureStage::new(payloads, CanonicalPayloadKind::Rc1Decision, first_key),
        FixtureStage::new(
            payloads,
            CanonicalPayloadKind::Rc2Authorization,
            first_key + 1,
        ),
        FixtureStage::new(
            payloads,
            CanonicalPayloadKind::Rc3Authorization,
            first_key + 2,
        ),
    ]
}

pub struct FixtureStage {
    payloads: Vec<(CanonicalPayloadKind, Vec<u8>)>,
    kind: CanonicalPayloadKind,
    key: u8,
}
pub struct RawFixtureStage {
    bytes: Vec<u8>,
    digest: [u8; 32],
    bootstrap: runne_project_owner_authority::VerifiedPromotionBootstrap,
}
impl RawFixtureStage {
    pub fn commit<S: StageTransitionStore>(
        &self,
        store: &mut S,
        promotion: &PromotionId,
        revision: u64,
        command: CommandId,
        kind: CanonicalPayloadKind,
    ) -> Result<runne_release_authority::TransactionOutcome, runne_release_authority::AuthorityError>
    {
        store.verify_and_commit_stage_transition(RawStageTransitionRequest {
            promotion,
            expected_revision: revision,
            command,
            kind: stage_kind(kind),
            bytes: &self.bytes,
            expected_sha256: self.digest,
            bootstrap: &self.bootstrap,
            publication_manifest: None,
        })
    }
    pub fn corrupt_signature(&mut self) {
        let last = self.bytes.len().saturating_sub(3);
        self.bytes[last] = b'A';
    }
    pub fn commit_publication<S: StageTransitionStore>(
        &self,
        store: &mut S,
        promotion: &PromotionId,
        revision: u64,
        command: CommandId,
        manifest: &runne_release_authority::InspectedCanonicalPayload,
    ) -> Result<runne_release_authority::TransactionOutcome, runne_release_authority::AuthorityError>
    {
        store.verify_and_commit_stage_transition(RawStageTransitionRequest {
            promotion,
            expected_revision: revision,
            command,
            kind: runne_promotion_contracts::CanonicalPayloadKind::Rc3Authorization,
            bytes: &self.bytes,
            expected_sha256: self.digest,
            bootstrap: &self.bootstrap,
            publication_manifest: Some(manifest),
        })
    }
}
impl FixtureStage {
    fn new(
        payloads: &[(CanonicalPayloadKind, Vec<u8>)],
        kind: CanonicalPayloadKind,
        key: u8,
    ) -> Self {
        Self {
            payloads: payloads.to_vec(),
            kind,
            key,
        }
    }
    pub fn commit<S: StageTransitionStore>(
        &self,
        store: &mut S,
        promotion: &PromotionId,
        revision: u64,
        command: CommandId,
    ) -> Result<runne_release_authority::TransactionOutcome, runne_release_authority::AuthorityError>
    {
        self.raw()
            .commit(store, promotion, revision, command, self.kind)
    }

    pub fn commit_with_nonce<S: StageTransitionStore>(
        &self,
        store: &mut S,
        promotion: &PromotionId,
        revision: u64,
        command: CommandId,
        nonce: &str,
    ) -> Result<runne_release_authority::TransactionOutcome, runne_release_authority::AuthorityError>
    {
        self.raw_with_nonce(nonce)
            .commit(store, promotion, revision, command, self.kind)
    }

    pub fn raw(&self) -> RawFixtureStage {
        self.raw_with_nonce(&format!("release-{}", self.key))
    }

    fn raw_with_nonce(&self, nonce: &str) -> RawFixtureStage {
        raw(&self.payloads, self.kind, self.key, nonce)
    }
}
fn stage_kind(kind: CanonicalPayloadKind) -> runne_promotion_contracts::CanonicalPayloadKind {
    match kind {
        CanonicalPayloadKind::Rc1Decision => {
            runne_promotion_contracts::CanonicalPayloadKind::Rc1Decision
        }
        CanonicalPayloadKind::Rc2Authorization => {
            runne_promotion_contracts::CanonicalPayloadKind::Rc2Authorization
        }
        CanonicalPayloadKind::Rc3Authorization => {
            runne_promotion_contracts::CanonicalPayloadKind::Rc3Authorization
        }
        _ => unreachable!("stage kind"),
    }
}
#[must_use]
pub fn bootstrap_digest() -> [u8; 32] {
    let (_, _, _, signed) = signed_bootstrap();
    signed.project_owner_authority_receipt_sha256
}
fn raw(
    payloads: &[(CanonicalPayloadKind, Vec<u8>)],
    kind: CanonicalPayloadKind,
    key_byte: u8,
    authorization_nonce: &str,
) -> RawFixtureStage {
    let (_, trust, predecessor, signed) = signed_bootstrap();
    let receipt = canonical_checked_in_promotion_bootstrap(&signed.unsigned, &signed.signature)
        .expect("signed bootstrap must encode");
    let bootstrap = verify_promotion_bootstrap_bytes(
        &receipt,
        signed.project_owner_authority_receipt_sha256,
        &trust,
        &predecessor,
        &BootstrapContext::valid(),
    )
    .expect("signed bootstrap must verify");
    let (role, schema_id) = stage(role_for(kind));
    let key = SigningKey::from_bytes(&[key_byte; 32]);
    let delegation = delegation(role, &key);
    let raw = payloads
        .iter()
        .find(|(payload_kind, _)| *payload_kind == kind)
        .map(|(_, bytes)| bytes)
        .expect("stage payload is present");
    let mut payload: serde_json::Value = serde_json::from_slice(raw).expect("payload JSON");
    if kind == CanonicalPayloadKind::Rc1Decision {
        payload.as_object_mut().expect("RC1 object").insert(
            "approver".into(),
            serde_json::json!({
                "principal_id": &delegation.principal_id,
                "account_id": &delegation.controlling_account_id,
                "lane_id": &delegation.lane_id,
                "key_id": &delegation.key_id,
                "signature_profile_id": &delegation.signature_profile_id
            }),
        );
    }
    let envelope = StageAuthorityEnvelopeV1 {
        schema_version: STAGE_ENVELOPE_SCHEMA_V1.into(),
        repository_id: "gocode".into(),
        bootstrap_receipt_sha256: bootstrap.receipt_sha256(),
        issuer_role: role.into(),
        issuer_principal_id: delegation.principal_id,
        issuer_controlling_account_id: delegation.controlling_account_id,
        issuer_lane_id: delegation.lane_id,
        issuer_key_id: delegation.key_id,
        issuer_key_epoch: 1,
        signature_profile_id: delegation.signature_profile_id,
        payload_schema_id: schema_id.into(),
        payload_schema_sha256: v3_trust_schema_digests()
            .expect("pins")
            .into_iter()
            .find(|pin| pin.schema_id == schema_id)
            .expect("stage schema pin")
            .schema_sha256,
        payload_sha256: Sha256::digest(canonical_stage_payload(&payload).expect("canonical"))
            .into(),
        payload,
        issued_at: "2026-08-13T00:00:02Z".into(),
        not_before: "2026-08-13T00:00:03Z".into(),
        expires_at: "2026-08-13T00:00:04Z".into(),
        revocation_epoch: 1,
        authorization_nonce: authorization_nonce.into(),
    };
    let domain = SigningDomain::new(STAGE_ENVELOPE_SCHEMA_V1, role, "gocode").expect("domain");
    let signature = key
        .sign(&signing_transcript(
            &domain,
            &runne_project_owner_authority::canonical_unsigned_stage_envelope(&envelope)
                .expect("canonical"),
        ))
        .to_bytes();
    let bytes = canonical_checked_in_stage_envelope(&envelope, &signature).expect("signed bytes");
    RawFixtureStage {
        digest: Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        bytes,
        bootstrap,
    }
}

fn role_for(kind: CanonicalPayloadKind) -> u8 {
    match kind {
        CanonicalPayloadKind::Rc1Decision => 1,
        CanonicalPayloadKind::Rc2Authorization => 2,
        CanonicalPayloadKind::Rc3Authorization => 3,
        _ => unreachable!("only stage payloads are verified"),
    }
}

fn stage(number: u8) -> (&'static str, &'static str) {
    match number {
        1 => (
            "RC1_QUALIFICATION_AUTHORIZER",
            "gocode.release.rc1-qualification-decision/1",
        ),
        2 => (
            "RC2_SIGNING_AUTHORIZER",
            "gocode.release.rc2-signing-authorization/1",
        ),
        3 => (
            "RC3_PUBLICATION_AUTHORIZER",
            "gocode.release.rc3-publication-authorization/1",
        ),
        _ => unreachable!("stage role"),
    }
}
