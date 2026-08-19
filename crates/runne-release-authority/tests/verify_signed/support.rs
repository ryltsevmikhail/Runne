use runne_release_authority::{
    CandidateBinding, CanonicalPayloadKind, CommandId, Digest, FixtureAdmission,
    FixturePrevalidatedSignedBundle, InMemoryPromotionStore, InspectedCanonicalPayload, Mutation,
    PromotionId, PromotionStore, RawRc2Evidence,
};
use sha2::{Digest as _, Sha256};

use super::{admission_support, verified_stage_support};

#[path = "support_authority.rs"]
mod authority;
#[allow(dead_code)] // Selected integration binaries consume this verifier fixture.
#[path = "evidence.rs"]
mod evidence;
#[path = "evidence_leased.rs"]
mod evidence_leased;
#[allow(unused_imports)]
pub use authority::signing_authorized_in_authority;

#[allow(dead_code)]
pub fn try_bundle(
    payloads: &[(CanonicalPayloadKind, Vec<u8>)],
) -> Result<FixturePrevalidatedSignedBundle, runne_release_authority::AuthorityError> {
    let (mut store, id, _) = signing_authorized();
    evidence_leased::try_bundle(
        &mut store,
        &id,
        payloads,
        &verified_stage_support::verified_stages(payloads)[1].payload(),
    )
}

#[allow(dead_code)] // RC2 lease integration test consumes the store-only closure helper.
pub fn leased_bundle(
    store: &mut InMemoryPromotionStore,
    id: &PromotionId,
    payloads: &[(CanonicalPayloadKind, Vec<u8>)],
) -> FixturePrevalidatedSignedBundle {
    evidence_leased::bundle(
        store,
        id,
        payloads,
        &verified_stage_support::verified_stages(payloads)[1].payload(),
    )
}

#[allow(dead_code)]
pub fn trust_snapshot(
    now: u64,
    revocation_epoch: u64,
    generation: u64,
) -> runne_release_authority::FixtureEvidenceTrustState {
    let prior = evidence::trust();
    runne_release_authority::FixtureEvidenceTrustState::try_new(
        now,
        revocation_epoch,
        generation,
        prior.registrations().to_vec(),
    )
    .unwrap()
}

#[allow(dead_code)] // Shared fixture support is consumed by selected integration binaries.
pub fn parsed(
    payloads: &[(CanonicalPayloadKind, Vec<u8>)],
    kind: CanonicalPayloadKind,
) -> Vec<InspectedCanonicalPayload> {
    payloads
        .iter()
        .filter(|(actual, _)| *actual == kind)
        .map(|(_, raw)| InspectedCanonicalPayload::parse(kind, raw).unwrap())
        .collect()
}

#[allow(dead_code)] // Only the store-facade contract test needs this raw fixture vector.
pub fn first_signing_effect_claim(
    payloads: &[(CanonicalPayloadKind, Vec<u8>)],
) -> (
    InspectedCanonicalPayload,
    InspectedCanonicalPayload,
    RawRc2Evidence,
) {
    let authorization = parsed(payloads, CanonicalPayloadKind::Rc2Authorization)
        .into_iter()
        .next()
        .unwrap();
    let record = parsed(payloads, CanonicalPayloadKind::ArtifactRecord)
        .into_iter()
        .next()
        .unwrap();
    let claim = evidence::claim(&record, &authorization, "linux-appimage", "linux", 1);
    (authorization, record, claim)
}

#[allow(dead_code)]
pub fn first_signing_effect_claim_with_expiry(
    payloads: &[(CanonicalPayloadKind, Vec<u8>)],
    expires_at: u64,
) -> (
    InspectedCanonicalPayload,
    InspectedCanonicalPayload,
    RawRc2Evidence,
) {
    let (authorization, record, _) = first_signing_effect_claim(payloads);
    let claim = evidence::claim_with_expiry(
        &record,
        &authorization,
        "linux-appimage",
        "linux",
        1,
        expires_at,
    );
    (authorization, record, claim)
}

#[allow(dead_code)]
pub fn native_evidence_for(
    record: &InspectedCanonicalPayload,
    effect: &runne_release_authority::FixtureVerifiedSigningEffect,
) -> RawRc2Evidence {
    evidence::native(record, effect, "linux")
}

#[allow(dead_code)]
pub fn native_evidence_for_with_expiry(
    record: &InspectedCanonicalPayload,
    effect: &runne_release_authority::FixtureVerifiedSigningEffect,
    expires_at: u64,
) -> RawRc2Evidence {
    evidence::native_with_expiry(record, effect, "linux", expires_at)
}

#[allow(dead_code)] // Selected integration binaries start from this fixed signing state.
pub fn signing_authorized() -> (
    InMemoryPromotionStore,
    PromotionId,
    Vec<(CanonicalPayloadKind, Vec<u8>)>,
) {
    signing_authorized_with("p")
}

#[allow(dead_code)] // Reserved for cross-promotion fixture setup.
pub fn signing_authorized_with(
    promotion: &str,
) -> (
    InMemoryPromotionStore,
    PromotionId,
    Vec<(CanonicalPayloadKind, Vec<u8>)>,
) {
    signing_authorized_with_nonce(promotion, "release-50")
}

fn signing_authorized_with_nonce(
    promotion: &str,
    nonce: &str,
) -> (
    InMemoryPromotionStore,
    PromotionId,
    Vec<(CanonicalPayloadKind, Vec<u8>)>,
) {
    let (mut store, id, payloads) = qualified_unsigned_with_nonce(promotion, nonce);
    let [_, rc2, _] = verified_stage_support::verified_stages(&payloads);
    rc2.commit(&mut store, &id, 3, CommandId::fixture("a"))
        .unwrap();
    store
        .set_rc2_evidence_trust_snapshot(&id, &evidence::trust())
        .unwrap();
    (store, id, payloads)
}

#[allow(dead_code)] // Some integration binaries begin from the qualified fixture state.
pub fn qualified_unsigned_with(
    promotion: &str,
) -> (
    InMemoryPromotionStore,
    PromotionId,
    Vec<(CanonicalPayloadKind, Vec<u8>)>,
) {
    qualified_unsigned_with_nonce(promotion, "release-50")
}

pub fn qualified_unsigned_with_nonce(
    promotion: &str,
    nonce: &str,
) -> (
    InMemoryPromotionStore,
    PromotionId,
    Vec<(CanonicalPayloadKind, Vec<u8>)>,
) {
    qualified_unsigned_with_store(promotion, nonce, InMemoryPromotionStore::default())
}

fn qualified_unsigned_with_store(
    promotion: &str,
    nonce: &str,
    mut store: InMemoryPromotionStore,
) -> (
    InMemoryPromotionStore,
    PromotionId,
    Vec<(CanonicalPayloadKind, Vec<u8>)>,
) {
    let binding = fixture_binding();
    let payloads = admission_support::admission_payloads_for(
        &binding.bootstrap().to_hex(),
        &binding.sha256().to_hex(),
    );
    let [rc1, _, _] = verified_stage_support::verified_stages(&payloads);
    let manifest = payloads
        .iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::UnsignedManifest)
        .map(|(kind, raw)| InspectedCanonicalPayload::parse(*kind, raw).unwrap())
        .unwrap();
    let id = PromotionId::fixture(promotion);
    store
        .transact(
            &id,
            0,
            CommandId::fixture("i"),
            Mutation::Ingest {
                binding,
                admission: Box::new(FixtureAdmission::ingest(binding, manifest).unwrap()),
            },
        )
        .unwrap();
    store
        .transact(&id, 1, CommandId::fixture("r"), Mutation::StartRc1Review {})
        .unwrap();
    rc1.commit_with_nonce(&mut store, &id, 2, CommandId::fixture("q"), nonce)
        .unwrap();
    (store, id, payloads)
}

#[allow(dead_code)] // Only durability tests need the pre-RC1 fixture state.
pub fn rc1_review_with(
    promotion: &str,
) -> (
    InMemoryPromotionStore,
    PromotionId,
    Vec<(CanonicalPayloadKind, Vec<u8>)>,
) {
    let binding = fixture_binding();
    let payloads = admission_support::admission_payloads_for(
        &binding.bootstrap().to_hex(),
        &binding.sha256().to_hex(),
    );
    let manifest = payloads
        .iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::UnsignedManifest)
        .map(|(kind, raw)| InspectedCanonicalPayload::parse(*kind, raw).unwrap())
        .unwrap();
    let id = PromotionId::fixture(promotion);
    let mut store = InMemoryPromotionStore::default();
    store
        .transact(
            &id,
            0,
            CommandId::fixture("i"),
            Mutation::Ingest {
                binding,
                admission: Box::new(FixtureAdmission::ingest(binding, manifest).unwrap()),
            },
        )
        .unwrap();
    store
        .transact(&id, 1, CommandId::fixture("r"), Mutation::StartRc1Review {})
        .unwrap();
    (store, id, payloads)
}

fn fixture_binding() -> CandidateBinding {
    let bootstrap = verified_stage_support::bootstrap_digest();
    let payloads = admission_support::admission_payloads_for(
        &Digest::fixture(bootstrap).to_hex(),
        &"aa".repeat(32),
    );
    let manifest = payloads
        .iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::UnsignedManifest)
        .map(|(_, raw)| raw)
        .unwrap();
    CandidateBinding::fixture_with_release_facts(
        [0xaa; 32],
        [0xaa; 32],
        bootstrap,
        [0xaa; 32],
        [0xaa; 32],
        Sha256::digest(&manifest[..manifest.len() - 1]).into(),
    )
}
