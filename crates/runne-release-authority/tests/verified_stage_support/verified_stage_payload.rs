#![allow(
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    reason = "fixture support keeps a move-only raw-envelope test flow"
)]

use runne_project_owner_authority::verify_stage_envelope_for_transition;
use runne_release_authority::{VerifiedStageTransition, inspect_verified_stage_envelope};

use super::{CanonicalPayloadKind, FixtureStage, RawFixtureStage};

struct Context;
static CONTEXT: Context = Context;
impl runne_project_owner_authority::StageVerificationContext for Context {
    fn admit_or_recover(
        &self,
        _: &runne_project_owner_authority::StageAdmissionRequest<'_>,
    ) -> Result<
        runne_project_owner_authority::StageAdmission,
        runne_project_owner_authority::AuthorityError,
    > {
        Ok(runne_project_owner_authority::StageAdmission::NewlyAdmitted)
    }
}

impl FixtureStage {
    #[must_use]
    pub fn transition(
        self,
        reservation: runne_promotion_contracts::StageTransitionReservation,
    ) -> VerifiedStageTransition {
        self.transition_with_context(reservation, &CONTEXT)
    }
    pub fn transition_with_context(
        self,
        reservation: runne_promotion_contracts::StageTransitionReservation,
        context: &dyn runne_project_owner_authority::StageVerificationContext,
    ) -> VerifiedStageTransition {
        verify(self.raw(), self.kind, reservation, context)
    }
    #[must_use]
    pub fn payload(&self) -> runne_release_authority::InspectedCanonicalPayload {
        let bytes = self
            .payloads
            .iter()
            .find(|(kind, _)| *kind == self.kind)
            .map(|(_, bytes)| bytes)
            .expect("fixture payload is present");
        runne_release_authority::InspectedCanonicalPayload::parse(self.kind, bytes)
            .expect("fixture stage payload is canonical")
    }
}

fn verify(
    raw: RawFixtureStage,
    kind: CanonicalPayloadKind,
    reservation: runne_promotion_contracts::StageTransitionReservation,
    context: &dyn runne_project_owner_authority::StageVerificationContext,
) -> VerifiedStageTransition {
    let envelope = verify_stage_envelope_for_transition(
        &raw.bytes,
        raw.digest,
        &raw.bootstrap,
        context,
        reservation,
    )
    .unwrap_or_else(|error| panic!("{kind:?}: {error:?}"));
    inspect_verified_stage_envelope(envelope).expect("release payload must inspect")
}
