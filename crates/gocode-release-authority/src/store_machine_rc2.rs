//! RC1-to-RC2 stage application helpers for the promotion state machine.

use crate::store_machine::Record;
use crate::{AuthorityError, PromotionState};

pub fn qualify(
    r: &mut Record,
    transition: crate::VerifiedStageTransition,
) -> Result<(), AuthorityError> {
    if r.state != Some(PromotionState::Rc1Review) {
        return Err(AuthorityError::InvalidTransition);
    }
    let (stage, admission, revalidated) = transition.into_parts();
    require_stage_reservation(
        r,
        &admission,
        revalidated,
        gocode_promotion_contracts::CanonicalPayloadKind::Rc1Decision,
    )?;
    r.admission_facts
        .as_ref()
        .ok_or(AuthorityError::BindingMismatch)?
        .validate_rc1(r.binding.ok_or(AuthorityError::BindingMismatch)?, &stage)?;
    r.rc1 = Some(stage.into_stored());
    r.stage_reservation = None;
    r.state = Some(PromotionState::QualifiedUnsigned);
    Ok(())
}

pub fn authorize_signing(
    r: &mut Record,
    transition: crate::VerifiedStageTransition,
) -> Result<(), AuthorityError> {
    if r.state != Some(PromotionState::QualifiedUnsigned) {
        return Err(AuthorityError::InvalidTransition);
    }
    let (stage, stage_admission, revalidated) = transition.into_parts();
    require_stage_reservation(
        r,
        &stage_admission,
        revalidated,
        gocode_promotion_contracts::CanonicalPayloadKind::Rc2Authorization,
    )?;
    let admission = r
        .admission_facts
        .as_ref()
        .ok_or(AuthorityError::BindingMismatch)?;
    let rc1 = r.rc1.as_ref().ok_or(AuthorityError::BindingMismatch)?;
    if rc1.bootstrap != stage.bootstrap() || rc1.root != *stage.root() {
        return Err(AuthorityError::BindingMismatch);
    }
    admission.validate_rc2(
        r.binding.ok_or(AuthorityError::BindingMismatch)?,
        rc1,
        &stage,
    )?;
    r.rc2_effect_authorization = Some(rc2_effect_authorization(
        &stage,
        r.authority_instance,
        r.revision,
        stage_admission
            .reservation()
            .map_err(|_| AuthorityError::BindingMismatch)?
            .promotion(),
    )?);
    r.rc2 = Some(stage.into_stored());
    r.stage_reservation = None;
    r.state = Some(PromotionState::SigningAuthorized);
    Ok(())
}

fn rc2_effect_authorization(
    stage: &crate::VerifiedStagePayload,
    authority_instance: crate::Digest,
    revision: u64,
    promotion: &str,
) -> Result<crate::FixtureRc2SigningAuthorization, AuthorityError> {
    let plan = stage
        .inspected()
        .rc2_plan()
        .ok_or(AuthorityError::BindingMismatch)?;
    crate::rc2_effect_lease::Rc2SigningAuthorizationFixture {
        authority_instance,
        promotion: promotion.into(),
        revision,
        authorization: crate::Digest::from_bytes(stage.sha256()),
        namespace: plan.effect_namespace,
        generation: plan.effect_generation,
        valid_from: plan.valid_from,
        expires_at: plan.expires_at,
        revocation_epoch: plan.revocation_epoch,
        workflow: plan.workflow,
        signer: plan.signer.join("/"),
        runner: plan.runner.join("/"),
        slots: plan
            .artifacts
            .map(|(slot, _, digest, length)| (slot, digest, length)),
    }
    .signing_authorized()
    .map_err(|_| AuthorityError::BindingMismatch)
}

fn require_stage_reservation(
    record: &Record,
    admission: &gocode_project_owner_authority::VerifiedStageAdmission,
    revalidated: bool,
    kind: gocode_promotion_contracts::CanonicalPayloadKind,
) -> Result<(), AuthorityError> {
    let stored = record
        .stage_reservation
        .as_ref()
        .ok_or(AuthorityError::BindingMismatch)?;
    let scope = admission
        .reservation()
        .map_err(|_| AuthorityError::BindingMismatch)?;
    (revalidated
        && scope.kind() == kind
        && scope.promotion() == stored.promotion.0
        && scope.revision() == stored.revision
        && scope.command() == stored.command
        && scope.fingerprint() == stored.fingerprint)
        .then_some(())
        .ok_or(AuthorityError::BindingMismatch)
}
