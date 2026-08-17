#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    AuthenticatedThresholdTransition, CommandId, Digest, DurableFixturePromotionAuthority,
    Mutation, PromotionState, PromotionStore, ThresholdAdmission, ThresholdAdmissionRequest,
    ThresholdFixtureStoreBinding, ThresholdVerificationContext, ThresholdVerificationState,
    admit_prevalidated_signed_bundle,
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
fn global_durable_authority_reopens_before_fixture_publication_attempt() {
    let path =
        std::env::temp_dir().join(format!("gocode-promotion-lifecycle-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (mut memory, id, payloads) = signing_support::signing_authorized();
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let bundle = signing_support::leased_bundle(&mut memory, &id, &payloads);
    let mut store =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding.clone(), &memory)
            .unwrap();
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    let proof = admit_prevalidated_signed_bundle(bundle, receipt, &Remote).unwrap();
    assert_eq!(
        store
            .transact(
                &id,
                4,
                CommandId::fixture("verify"),
                Mutation::VerifySigned {
                    proof: Box::new(proof)
                },
            )
            .unwrap()
            .state,
        PromotionState::SignedEnvelopesVerified
    );
    assert_eq!(
        store
            .acknowledge_threshold_completion(&id, 5, CommandId::fixture("ack"), &Remote)
            .unwrap()
            .revision,
        6
    );
    assert_eq!(
        store
            .transact(
                &id,
                6,
                CommandId::fixture("r3"),
                Mutation::StartRc3Review {}
            )
            .unwrap()
            .state,
        PromotionState::Rc3Review
    );
    drop(store);
    let mut store = DurableFixturePromotionAuthority::reopen(&path, binding.clone()).unwrap();
    let manifest = payloads
        .iter()
        .find(|(kind, _)| {
            *kind == gocode_release_authority::CanonicalPayloadKind::PublicationManifest
        })
        .map(|(kind, raw)| gocode_release_authority::InspectedCanonicalPayload::parse(*kind, raw))
        .unwrap();
    assert_eq!(
        manifest,
        Err(gocode_release_authority::AuthorityError::AuthorityVersionSuperseded)
    );
    let [_, _, stage] = verified_stage_support::verified_stages(&payloads);
    assert_eq!(
        stage.raw().commit(
            &mut store,
            &id,
            7,
            CommandId::fixture("publish"),
            gocode_release_authority::CanonicalPayloadKind::Rc3Authorization
        ),
        Err(gocode_release_authority::AuthorityError::AuthorityVersionSuperseded)
    );
    drop(store);
    let reopened = DurableFixturePromotionAuthority::reopen(&path, binding).unwrap();
    assert_eq!(reopened.snapshot(&id).unwrap().revision, 7);
    std::fs::remove_file(path).unwrap();
}
