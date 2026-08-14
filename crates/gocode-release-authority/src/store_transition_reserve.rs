//! Atomic final RC2 reservation and one-time effect closure consumption.

use crate::{
    AuthorityError, CommandId, Digest, PromotionId, PromotionState, SigningAuthorizedReceipt,
};

pub fn reserve(
    record: &mut crate::store_machine::Record,
    effects: &mut crate::FixtureRc2EffectLeaseLedger,
    id: &PromotionId,
    expected: u64,
    command: CommandId,
    bundle: &crate::FixturePrevalidatedSignedBundle,
) -> Result<SigningAuthorizedReceipt, AuthorityError> {
    crate::store_command::require_canonical(&command)?;
    if record.revision >= u64::MAX - 1 {
        return Err(AuthorityError::StaleRevision);
    }
    if record.commands.contains_key(command.as_str()) {
        return Err(AuthorityError::CommandReplayDiverged);
    }
    let authorization = Digest::from_bytes(
        record
            .rc2
            .as_ref()
            .ok_or(AuthorityError::BindingMismatch)?
            .sha256,
    );
    let fingerprint = crate::store_command::reservation_fingerprint(
        record.authority_instance,
        id,
        expected,
        &command,
        authorization,
        bundle,
    );
    if bundle.authorization() != authorization
        || bundle.authority_instance() != record.authority_instance
        || bundle.candidate()
            != record
                .binding
                .ok_or(AuthorityError::BindingMismatch)?
                .candidate()
    {
        return Err(AuthorityError::BindingMismatch);
    }
    record.rc2_evidence_trust.revalidates(bundle)?;
    if let Some(reservation) = &record.reservation {
        return reservation
            .matches(
                record.authority_instance,
                id,
                expected,
                authorization,
                &command,
                fingerprint,
                bundle.commitment(),
                bundle.evidence_trust(),
                bundle.evidence_expires_at(),
            )
            .then(|| SigningAuthorizedReceipt {
                authority_instance: record.authority_instance,
                promotion: id.clone(),
                revision: expected,
                authorization,
                command: command.into_inner(),
                commitment: bundle.commitment(),
            })
            .ok_or(AuthorityError::CommandReplayDiverged);
    }
    if record.state != Some(PromotionState::SigningAuthorized) {
        return Err(AuthorityError::InvalidTransition);
    }
    if record.revision != expected {
        return Err(AuthorityError::StaleRevision);
    }
    let closure = bundle.take_effect_closure()?;
    let expected_promotion = id.0.clone();
    if (closure.promotion != expected_promotion
        || closure.authority_instance != record.authority_instance)
        || closure.authorization != authorization
        || closure.commitment != bundle.commitment()
    {
        bundle.restore_effect_closure(closure);
        return Err(AuthorityError::BindingMismatch);
    }
    if effects.consume_completed_closure(closure).is_err() {
        return Err(AuthorityError::BindingMismatch);
    }
    record.reservation = Some(crate::store_machine::StoredVerifySignedReservation {
        authority_instance: record.authority_instance,
        promotion: id.clone(),
        revision: expected,
        authorization,
        command: command.as_str().into(),
        fingerprint,
        commitment: bundle.commitment(),
        evidence_trust: bundle.evidence_trust(),
        evidence_expires_at: bundle.evidence_expires_at(),
    });
    Ok(SigningAuthorizedReceipt {
        authority_instance: record.authority_instance,
        promotion: id.clone(),
        revision: expected,
        authorization,
        command: command.into_inner(),
        commitment: bundle.commitment(),
    })
}
