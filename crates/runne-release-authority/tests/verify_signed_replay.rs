#![cfg(feature = "fixture-only")]

use runne_release_authority::{
    AuthorityError, CommandId, Mutation, PromotionStore, admit_prevalidated_signed_bundle,
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

#[test]
fn proof_cannot_be_applied_under_a_substituted_command() {
    let (mut store, id, payloads) = signing_support::signing_authorized();
    let bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    // A real threshold context is not required: this assertion is local proof-command binding.
    let context = unreachable_context::Context;
    let proof = admit_prevalidated_signed_bundle(bundle, receipt, &context).unwrap();
    assert_eq!(
        store.transact(
            &id,
            4,
            CommandId::fixture("substituted"),
            Mutation::VerifySigned {
                proof: Box::new(proof)
            }
        ),
        Err(AuthorityError::CommandReplayDiverged)
    );
}

mod unreachable_context {
    use runne_release_authority::*;
    pub struct Context;
    impl ThresholdVerificationContext for Context {
        fn recover_existing(
            &self,
            _: &ThresholdAdmissionRequest<'_>,
        ) -> Result<Option<ThresholdAdmission>, AuthorityError> {
            Ok(Some(ThresholdAdmission::ExistingSame {
                admission_id: Digest::fixture([8; 32]),
            }))
        }
        fn trusted_state_and_now(
            &self,
        ) -> Result<(ThresholdVerificationState, u64), AuthorityError> {
            unreachable!()
        }
        fn persist_new(
            &self,
            _: AuthenticatedThresholdTransition,
        ) -> Result<ThresholdAdmission, AuthorityError> {
            unreachable!()
        }
        fn acknowledge_or_recover(
            &self,
            _: &ThresholdAckRequest<'_>,
        ) -> Result<ThresholdAckProof, AuthorityError> {
            unreachable!()
        }
    }
}
