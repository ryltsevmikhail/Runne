use std::cell::{Cell, RefCell};

use crate::{AuthorityError, AuthorityStateSnapshot, DurableAdmission, PersistedAdmission};

pub trait ModelRequest: Clone + Eq {
    fn expected(&self) -> &AuthorityStateSnapshot;
    fn newly_admitted_state(&self) -> &AuthorityStateSnapshot;
    fn persisted(&self) -> PersistedAdmission;
    fn same_admission_as(&self, stored: &Self) -> bool;
}

macro_rules! model_request {
    ($type:ty) => {
        impl ModelRequest for $type {
            fn expected(&self) -> &AuthorityStateSnapshot {
                &self.expected
            }
            fn newly_admitted_state(&self) -> &AuthorityStateSnapshot {
                &self.newly_admitted_state
            }
            fn persisted(&self) -> PersistedAdmission {
                PersistedAdmission {
                    reservation: self.reservation.clone(),
                    outcome: self.outcome.clone(),
                }
            }
            fn same_admission_as(&self, stored: &Self) -> bool {
                <$type>::same_admission_as(self, stored)
            }
        }
    };
}
model_request!(crate::ReceiptV5AdmissionRequest);
model_request!(crate::StageEnvelopeAdmissionRequest);
model_request!(crate::EvidenceEnvelopeAdmissionRequest);
model_request!(crate::DestinationAllowlistAdmissionRequest);

pub struct StatefulStore<R> {
    pub state: RefCell<AuthorityStateSnapshot>,
    pub stored: RefCell<Option<R>>,
    pub calls: Cell<u16>,
    pub recoveries: Cell<u16>,
    pub new_receipt_calls: Cell<u16>,
    pub receipt_recovery_lookups: Cell<u16>,
    pub race: Cell<bool>,
    pub after_expiry: Cell<bool>,
    pub wrong_state: Cell<bool>,
    pub wrong_persisted: Cell<bool>,
    pub wrong_variant: Cell<bool>,
}

impl<R: ModelRequest> StatefulStore<R> {
    pub fn new(state: AuthorityStateSnapshot) -> Self {
        Self {
            state: RefCell::new(state),
            stored: RefCell::new(None),
            calls: Cell::new(0),
            recoveries: Cell::new(0),
            new_receipt_calls: Cell::new(0),
            receipt_recovery_lookups: Cell::new(0),
            race: Cell::new(false),
            after_expiry: Cell::new(false),
            wrong_state: Cell::new(false),
            wrong_persisted: Cell::new(false),
            wrong_variant: Cell::new(false),
        }
    }

    pub fn admit(&self, request: &R) -> Result<DurableAdmission, AuthorityError> {
        self.calls.set(self.calls.get() + 1);
        if self.race.replace(false) {
            self.state.borrow_mut().durable_generation += 1;
        }
        if &*self.state.borrow() != request.expected() {
            return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
        }
        let stored = self.stored.borrow();
        if let Some(existing) = stored.as_ref() {
            if !request.same_admission_as(existing) {
                return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
            }
            self.recoveries.set(self.recoveries.get() + 1);
            return Ok(self.result(false, request));
        }
        drop(stored);
        if self.after_expiry.get() {
            return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
        }
        *self.state.borrow_mut() = request.newly_admitted_state().clone();
        *self.stored.borrow_mut() = Some(request.clone());
        Ok(self.result(true, request))
    }

    fn result(&self, newly_admitted: bool, request: &R) -> DurableAdmission {
        let mut state = self.state.borrow().clone();
        if self.wrong_state.get() {
            state.durable_generation += 7;
        }
        let mut persisted = request.persisted();
        if self.wrong_persisted.get() {
            persisted.reservation.0[0] ^= 1;
        }
        match (newly_admitted, self.wrong_variant.get()) {
            (true, false) | (false, true) => DurableAdmission::NewlyAdmitted { persisted, state },
            (false, false) | (true, true) => DurableAdmission::ExistingSame { persisted, state },
        }
    }
}

pub struct ReceiptContext(pub StatefulStore<crate::ReceiptV5AdmissionRequest>);
impl crate::ReceiptV5VerificationContext for ReceiptContext {
    fn authority_store_profile(&self) -> Result<&str, AuthorityError> {
        Ok("store")
    }
    fn read_authority_state(&self) -> Result<AuthorityStateSnapshot, AuthorityError> {
        Ok(self.0.state.borrow().clone())
    }
    fn admit_receipt_v5(
        &self,
        request: &crate::ReceiptV5AdmissionRequest,
    ) -> Result<crate::NewlyAdmittedReceiptV5, AuthorityError> {
        self.0.calls.set(self.0.calls.get() + 1);
        self.0
            .new_receipt_calls
            .set(self.0.new_receipt_calls.get() + 1);
        if self.0.race.replace(false) {
            self.0.state.borrow_mut().durable_generation += 1;
        }
        if &*self.0.state.borrow() != request.expected() || self.0.stored.borrow().is_some() {
            return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
        }
        if self.0.after_expiry.get() {
            return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
        }
        *self.0.state.borrow_mut() = request.newly_admitted_state.clone();
        *self.0.stored.borrow_mut() = Some(request.clone());
        let mut state = self.0.state.borrow().clone();
        let mut persisted = request.persisted();
        corrupt_result(&self.0, &mut state, &mut persisted);
        Ok(crate::NewlyAdmittedReceiptV5 { persisted, state })
    }
    fn recover_receipt_v5(
        &self,
        request: &crate::ReceiptV5RecoveryRequest,
    ) -> Result<crate::ExistingSameReceiptV5, AuthorityError> {
        self.0.calls.set(self.0.calls.get() + 1);
        self.0
            .receipt_recovery_lookups
            .set(self.0.receipt_recovery_lookups.get() + 1);
        if self.0.state.borrow().ne(&request.expected) {
            return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
        }
        let stored = self.0.stored.borrow();
        let existing = stored
            .as_ref()
            .ok_or(AuthorityError::PromotionBootstrapAdmissionConflict)?;
        if !request.same_admission_as(existing) {
            return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
        }
        self.0.recoveries.set(self.0.recoveries.get() + 1);
        let mut state = self.0.state.borrow().clone();
        let mut persisted = crate::PersistedAdmission {
            reservation: request.reservation.clone(),
            outcome: request.outcome.clone(),
        };
        corrupt_result(&self.0, &mut state, &mut persisted);
        Ok(crate::ExistingSameReceiptV5 { persisted, state })
    }
}

fn corrupt_result<R>(
    store: &StatefulStore<R>,
    state: &mut AuthorityStateSnapshot,
    persisted: &mut PersistedAdmission,
) {
    if store.wrong_state.get() {
        state.durable_generation += 7;
    }
    if store.wrong_persisted.get() {
        persisted.reservation.0[0] ^= 1;
    }
}

pub struct StageContext(pub StatefulStore<crate::StageEnvelopeAdmissionRequest>);
impl crate::V5EnvelopeVerificationContext for StageContext {
    fn read_authority_state(&self) -> Result<AuthorityStateSnapshot, AuthorityError> {
        Ok(self.0.state.borrow().clone())
    }
    fn admit_or_recover_stage(
        &self,
        request: &crate::StageEnvelopeAdmissionRequest,
    ) -> Result<DurableAdmission, AuthorityError> {
        self.0.admit(request)
    }
    fn admit_or_recover_evidence(
        &self,
        _: &crate::EvidenceEnvelopeAdmissionRequest,
    ) -> Result<DurableAdmission, AuthorityError> {
        unreachable!()
    }
}

pub struct EvidenceContext(pub StatefulStore<crate::EvidenceEnvelopeAdmissionRequest>);
impl crate::V5EnvelopeVerificationContext for EvidenceContext {
    fn read_authority_state(&self) -> Result<AuthorityStateSnapshot, AuthorityError> {
        Ok(self.0.state.borrow().clone())
    }
    fn admit_or_recover_stage(
        &self,
        _: &crate::StageEnvelopeAdmissionRequest,
    ) -> Result<DurableAdmission, AuthorityError> {
        unreachable!()
    }
    fn admit_or_recover_evidence(
        &self,
        request: &crate::EvidenceEnvelopeAdmissionRequest,
    ) -> Result<DurableAdmission, AuthorityError> {
        self.0.admit(request)
    }
}

pub struct AllowlistContext(pub StatefulStore<crate::DestinationAllowlistAdmissionRequest>);
impl crate::DestinationAllowlistVerificationContext for AllowlistContext {
    fn read_authority_state(&self) -> Result<AuthorityStateSnapshot, AuthorityError> {
        Ok(self.0.state.borrow().clone())
    }
    fn admit_or_recover_allowlist(
        &self,
        request: &crate::DestinationAllowlistAdmissionRequest,
    ) -> Result<DurableAdmission, AuthorityError> {
        self.0.admit(request)
    }
}
