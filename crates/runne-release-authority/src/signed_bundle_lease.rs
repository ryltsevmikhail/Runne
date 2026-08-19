#![allow(clippy::missing_errors_doc, clippy::too_many_arguments)] // Atomic bundle boundary.
use crate::{
    AuthorityError, FixturePrevalidatedSignedBundle, FixtureRc2EffectLeaseLedger,
    FixtureRc2SigningAuthorization, FixtureVerifiedNativeEvidence, FixtureVerifiedSigningEffect,
    FixtureVerifiedSigningReview, FixtureVerifiedUpdateMetadataIssuance, InspectedCanonicalPayload,
};

impl FixturePrevalidatedSignedBundle {
    /// Mint one internal closure receipt from the three completed exact pre-sign leases.
    pub(crate) fn prevalidate_with_completed_leases(
        authority_instance: crate::Digest,
        payloads: &[InspectedCanonicalPayload],
        effects: [FixtureVerifiedSigningEffect; 3],
        evidence: [FixtureVerifiedNativeEvidence; 3],
        review: FixtureVerifiedSigningReview,
        issuance: FixtureVerifiedUpdateMetadataIssuance,
        authorization: &InspectedCanonicalPayload,
        leases: &FixtureRc2EffectLeaseLedger,
        lease_authorization: &FixtureRc2SigningAuthorization,
    ) -> Result<Self, AuthorityError> {
        let bundle = Self::prevalidate(
            authority_instance,
            payloads,
            effects,
            evidence,
            review,
            issuance,
            authorization,
        )?;
        let commitment = bundle.commitment();
        let closure = leases
            .mint_completed_closure(lease_authorization, commitment)
            .map_err(|_| AuthorityError::BindingMismatch)?;
        bundle.attach_effect_closure(closure)?;
        Ok(bundle)
    }
}
