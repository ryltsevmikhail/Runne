//! Store-local stage admission context used only while the durable store lock is held.

use std::cell::RefCell;

use runne_project_owner_authority::{
    AuthorityError, StageAdmission, StageAdmissionRequest, StageVerificationContext,
};

pub struct RecordStageContext<'a> {
    record: RefCell<&'a mut crate::store_machine::Record>,
}
impl<'a> RecordStageContext<'a> {
    pub const fn new(record: &'a mut crate::store_machine::Record) -> Self {
        Self {
            record: RefCell::new(record),
        }
    }
}
impl StageVerificationContext for RecordStageContext<'_> {
    fn admit_or_recover(
        &self,
        request: &StageAdmissionRequest<'_>,
    ) -> Result<StageAdmission, AuthorityError> {
        let mut record = self.record.borrow_mut();
        let trust = record.stage_trust.clone();
        let claim =
            crate::store_stage_claim::StoredStageClaim::from_request(request, trust.role_floor);
        if let Some(existing) = record.stage_claims.get(request.scope.authorization_nonce) {
            return if existing == &claim
                && request.bootstrap_admission_scope.root_revocation_epoch() == trust.root_epoch
            {
                Ok(StageAdmission::ExistingSame)
            } else {
                Err(AuthorityError::ReplayedStageEnvelope)
            };
        }
        if request.bootstrap_admission_scope.root_revocation_epoch() != trust.root_epoch
            || request.envelope_revocation_epoch < trust.role_floor
            || request.payload_revocation_epoch != request.envelope_revocation_epoch
        {
            return Err(AuthorityError::StaleOrRevokedStageEnvelope);
        }
        if !within_utc(
            &trust.utc,
            request.bootstrap_validity.not_before(),
            request.bootstrap_validity.expires_at(),
        ) || !within_utc(
            &trust.utc,
            request.envelope_not_before,
            request.envelope_expires_at,
        ) {
            return Err(AuthorityError::StaleOrRevokedStageEnvelope);
        }
        let reservation = record
            .stage_reservation
            .as_ref()
            .ok_or(AuthorityError::ReplayedStageEnvelope)?;
        let scope = request.scope.reservation;
        if scope.promotion() != reservation.promotion.0
            || scope.revision() != reservation.revision
            || scope.command() != reservation.command
            || scope.fingerprint() != reservation.fingerprint
        {
            return Err(AuthorityError::ReplayedStageEnvelope);
        }
        if trust.now < request.payload_valid_from || trust.now >= request.payload_expires_at {
            return Err(AuthorityError::StaleOrRevokedStageEnvelope);
        }
        record
            .stage_claims
            .insert(request.scope.authorization_nonce.into(), claim);
        Ok(StageAdmission::NewlyAdmitted)
    }
}

fn within_utc(now: &str, not_before: &str, expires_at: &str) -> bool {
    not_before <= now && now < expires_at
}
