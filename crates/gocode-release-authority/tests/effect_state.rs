#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    AuthenticatedThresholdTransition, AuthorityError, CanonicalPayloadKind, CommandId, Digest,
    Mutation, PromotionStore, ThresholdAdmission, ThresholdAdmissionRequest,
    ThresholdVerificationContext, ThresholdVerificationState, admit_prevalidated_signed_bundle,
};

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "verify_signed/support.rs"]
mod signing_support;
#[path = "canonical_wire/support.rs"]
mod support;
mod verified_stage_support;

struct Remote;
impl ThresholdVerificationContext for Remote {
    fn recover_existing(
        &self,
        _: &ThresholdAdmissionRequest<'_>,
    ) -> Result<Option<ThresholdAdmission>, gocode_release_authority::AuthorityError> {
        Ok(Some(ThresholdAdmission::ExistingSame {
            admission_id: Digest::fixture([9; 32]),
        }))
    }
    fn trusted_state_and_now(
        &self,
    ) -> Result<(ThresholdVerificationState, u64), gocode_release_authority::AuthorityError> {
        unreachable!()
    }
    fn persist_new(
        &self,
        _: AuthenticatedThresholdTransition,
    ) -> Result<ThresholdAdmission, gocode_release_authority::AuthorityError> {
        Ok(ThresholdAdmission::NewlyAdmitted {
            admission_id: Digest::fixture([9; 32]),
        })
    }
    fn acknowledge_or_recover(
        &self,
        request: &gocode_release_authority::ThresholdAckRequest<'_>,
    ) -> Result<gocode_release_authority::ThresholdAckProof, gocode_release_authority::AuthorityError>
    {
        Ok(request.acknowledge())
    }
}

#[test]
fn legacy_rc3_publication_ingress_is_superseded_before_effect_state_mutation() {
    let (mut store, id, payloads) = signing_support::signing_authorized();
    let bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    let proof = admit_prevalidated_signed_bundle(bundle, receipt, &Remote).unwrap();
    store
        .transact(
            &id,
            4,
            CommandId::fixture("verify"),
            Mutation::VerifySigned {
                proof: Box::new(proof),
            },
        )
        .unwrap();
    store
        .acknowledge_threshold_completion(&id, 5, CommandId::fixture("ack"), &Remote)
        .unwrap();
    store
        .transact(
            &id,
            6,
            CommandId::fixture("r3"),
            Mutation::StartRc3Review {},
        )
        .unwrap();
    let manifest = payloads
        .iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::PublicationManifest)
        .map(|(kind, raw)| gocode_release_authority::InspectedCanonicalPayload::parse(*kind, raw))
        .unwrap();
    assert_eq!(manifest, Err(AuthorityError::AuthorityVersionSuperseded));
    let [_, _, stage] = verified_stage_support::verified_stages(&payloads);
    assert_eq!(
        stage.raw().commit(
            &mut store,
            &id,
            7,
            CommandId::fixture("publish"),
            CanonicalPayloadKind::Rc3Authorization
        ),
        Err(AuthorityError::AuthorityVersionSuperseded)
    );
}
