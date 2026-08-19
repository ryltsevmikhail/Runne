use runne_release_authority::{
    CanonicalPayloadKind, FixturePrevalidatedSignedBundle, InMemoryPromotionStore,
    InspectedCanonicalPayload, PromotionId,
};

use super::evidence;

#[allow(dead_code)] // Support module is shared by integration binaries.
pub(super) fn bundle(
    store: &mut InMemoryPromotionStore,
    id: &PromotionId,
    payloads: &[(CanonicalPayloadKind, Vec<u8>)],
    authorization: &InspectedCanonicalPayload,
) -> FixturePrevalidatedSignedBundle {
    try_bundle(store, id, payloads, authorization).unwrap()
}

pub(super) fn try_bundle(
    store: &mut InMemoryPromotionStore,
    id: &PromotionId,
    payloads: &[(CanonicalPayloadKind, Vec<u8>)],
    authorization: &InspectedCanonicalPayload,
) -> Result<FixturePrevalidatedSignedBundle, runne_release_authority::AuthorityError> {
    let parsed = payloads
        .iter()
        .filter(|(kind, _)| {
            matches!(
                kind,
                CanonicalPayloadKind::UnsignedManifest
                    | CanonicalPayloadKind::ArtifactRecord
                    | CanonicalPayloadKind::Inventory
                    | CanonicalPayloadKind::ThresholdMetadata
                    | CanonicalPayloadKind::VerificationReport
            )
        })
        .map(|(kind, raw)| InspectedCanonicalPayload::parse(*kind, raw))
        .collect::<Result<Vec<_>, _>>()?;
    let records = parsed
        .iter()
        .filter(|item| item.kind() == CanonicalPayloadKind::ArtifactRecord)
        .collect::<Vec<_>>();
    let inventory = parsed
        .iter()
        .find(|item| item.kind() == CanonicalPayloadKind::Inventory)
        .ok_or(runne_release_authority::AuthorityError::BindingMismatch)?;
    let metadata = parsed
        .iter()
        .find(|item| item.kind() == CanonicalPayloadKind::ThresholdMetadata)
        .ok_or(runne_release_authority::AuthorityError::BindingMismatch)?;
    let mut leases = store
        .reserve_rc2_signing_effects(id, 4)
        .map_err(|_| runne_release_authority::AuthorityError::BindingMismatch)?;
    let slots = ["linux-appimage", "linux-deb", "windows-installer-unsigned"];
    let platforms = ["linux", "linux", "windows"];
    let lengths = [1, 2, 5];
    let mut effects = Vec::new();
    let mut native = Vec::new();
    for index in 0..3 {
        let effect = store.verify_rc2_signing_effect_with_lease(
            id,
            evidence::claim(
                records[index],
                authorization,
                slots[index],
                platforms[index],
                lengths[index],
            ),
            authorization,
            leases
                .take(slots[index])
                .map_err(|_| runne_release_authority::AuthorityError::BindingMismatch)?,
        )?;
        eprintln!("effect {index}");
        let retained = effect.effect().clone();
        native.push(store.verify_rc2_native_evidence_closing_lease(
            id,
            evidence::native(records[index], &retained, platforms[index]),
            records[index],
            effect,
        )?);
        effects.push(retained);
    }
    let effects: [runne_release_authority::FixtureVerifiedSigningEffect; 3] = effects
        .try_into()
        .map_err(|_| runne_release_authority::AuthorityError::BindingMismatch)?;
    let native: [runne_release_authority::FixtureVerifiedNativeEvidence; 3] = native
        .try_into()
        .map_err(|_| runne_release_authority::AuthorityError::BindingMismatch)?;
    let review = store.verify_rc2_signing_review(
        id,
        evidence::review(authorization, inventory, &native),
        authorization,
        inventory,
        &native,
    )?;
    let issuance = store.verify_rc2_update_metadata_issuance(
        id,
        evidence::issuance(authorization, inventory, metadata),
        authorization,
        inventory,
        metadata,
    )?;
    store
        .prevalidate_rc2_bundle_with_claims(
            id,
            &parsed,
            effects,
            native,
            review,
            issuance,
            authorization,
        )
        .map_err(|_| runne_release_authority::AuthorityError::BindingMismatch)
}
