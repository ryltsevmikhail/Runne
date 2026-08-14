use super::*;

#[allow(dead_code)]
pub fn signing_authorized_in_authority(
    promotion: &str,
    authority_instance: Digest,
) -> (
    InMemoryPromotionStore,
    PromotionId,
    Vec<(CanonicalPayloadKind, Vec<u8>)>,
) {
    let (mut store, id, payloads) = qualified_unsigned_with_store(
        promotion,
        "release-50",
        InMemoryPromotionStore::fixture_with_authority_instance(authority_instance),
    );
    let [_, rc2, _] = verified_stage_support::verified_stages(&payloads);
    rc2.commit(&mut store, &id, 3, CommandId::fixture("a"))
        .unwrap();
    store
        .set_rc2_evidence_trust_snapshot(&id, &evidence::trust())
        .unwrap();
    (store, id, payloads)
}
