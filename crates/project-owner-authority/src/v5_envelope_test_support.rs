//! Shared deterministic contexts and fixtures for V5 wire tests.

use std::cell::{Cell, RefCell};

use crate::{AuthorityError, ReceiptV5VerificationContext, V5EnvelopeVerificationContext};

#[path = "v5_envelope_test_support_allowlist.rs"]
mod v5_envelope_test_support_allowlist;
#[path = "v5_envelope_test_support_chain.rs"]
mod v5_envelope_test_support_chain;
#[path = "v5_envelope_test_support_envelopes.rs"]
mod v5_envelope_test_support_envelopes;

pub use v5_envelope_test_support_allowlist::*;
pub use v5_envelope_test_support_chain::*;
pub use v5_envelope_test_support_envelopes::*;

pub struct Receipt5Context(pub Cell<u8>);
impl ReceiptV5VerificationContext for Receipt5Context {
    fn authority_store_profile(&self) -> Result<&str, AuthorityError> {
        Ok("store")
    }
    fn read_authority_state(&self) -> Result<crate::AuthorityStateSnapshot, AuthorityError> {
        Ok(state(4))
    }
    fn admit_receipt_v5(
        &self,
        request: &crate::ReceiptV5AdmissionRequest,
    ) -> Result<crate::NewlyAdmittedReceiptV5, AuthorityError> {
        self.0.set(self.0.get() + 1);
        Ok(crate::NewlyAdmittedReceiptV5 {
            persisted: crate::PersistedAdmission {
                reservation: request.reservation.clone(),
                outcome: request.outcome.clone(),
            },
            state: request.newly_admitted_state.clone(),
        })
    }
    fn recover_receipt_v5(
        &self,
        _: &crate::ReceiptV5RecoveryRequest,
    ) -> Result<crate::ExistingSameReceiptV5, AuthorityError> {
        Err(AuthorityError::PromotionBootstrapAdmissionConflict)
    }
}

pub struct EnvelopeContext(pub Cell<u8>);
impl V5EnvelopeVerificationContext for EnvelopeContext {
    fn read_authority_state(&self) -> Result<crate::AuthorityStateSnapshot, AuthorityError> {
        Ok(state(5))
    }
    fn admit_or_recover_stage(
        &self,
        request: &crate::StageEnvelopeAdmissionRequest,
    ) -> Result<crate::DurableAdmission, AuthorityError> {
        self.0.set(self.0.get() + 1);
        Ok(new_admission(request))
    }
    fn admit_or_recover_evidence(
        &self,
        request: &crate::EvidenceEnvelopeAdmissionRequest,
    ) -> Result<crate::DurableAdmission, AuthorityError> {
        self.0.set(self.0.get() + 1);
        Ok(new_admission(request))
    }
}

pub struct ReplayEnvelopeContext(pub RefCell<Vec<String>>);
impl V5EnvelopeVerificationContext for ReplayEnvelopeContext {
    fn read_authority_state(&self) -> Result<crate::AuthorityStateSnapshot, AuthorityError> {
        Ok(state(5))
    }
    fn admit_or_recover_stage(
        &self,
        request: &crate::StageEnvelopeAdmissionRequest,
    ) -> Result<crate::DurableAdmission, AuthorityError> {
        let mut seen = self.0.borrow_mut();
        if seen.iter().any(|nonce| nonce == &request.scope.nonce) {
            return Err(AuthorityError::ReplayedStageEnvelope);
        }
        seen.push(request.scope.nonce.clone());
        Ok(new_admission(request))
    }
    fn admit_or_recover_evidence(
        &self,
        request: &crate::EvidenceEnvelopeAdmissionRequest,
    ) -> Result<crate::DurableAdmission, AuthorityError> {
        let mut seen = self.0.borrow_mut();
        if seen.iter().any(|nonce| nonce == &request.scope.nonce) {
            return Err(AuthorityError::ReplayedStageEnvelope);
        }
        seen.push(request.scope.nonce.clone());
        Ok(new_admission(request))
    }
}

pub struct RejectingEnvelopeContext(pub Cell<u8>);
impl V5EnvelopeVerificationContext for RejectingEnvelopeContext {
    fn read_authority_state(&self) -> Result<crate::AuthorityStateSnapshot, AuthorityError> {
        Ok(state(5))
    }
    fn admit_or_recover_stage(
        &self,
        _: &crate::StageEnvelopeAdmissionRequest,
    ) -> Result<crate::DurableAdmission, AuthorityError> {
        self.0.set(self.0.get() + 1);
        Err(AuthorityError::StaleOrRevokedStageEnvelope)
    }
    fn admit_or_recover_evidence(
        &self,
        _: &crate::EvidenceEnvelopeAdmissionRequest,
    ) -> Result<crate::DurableAdmission, AuthorityError> {
        self.0.set(self.0.get() + 1);
        Err(AuthorityError::StaleOrRevokedStageEnvelope)
    }
}

pub struct AllowlistContext(pub Cell<u8>);
impl crate::DestinationAllowlistVerificationContext for AllowlistContext {
    fn read_authority_state(&self) -> Result<crate::AuthorityStateSnapshot, AuthorityError> {
        Ok(state(5))
    }
    fn admit_or_recover_allowlist(
        &self,
        request: &crate::DestinationAllowlistAdmissionRequest,
    ) -> Result<crate::DurableAdmission, AuthorityError> {
        self.0.set(self.0.get() + 1);
        Ok(new_admission(request))
    }
}

pub struct RejectingAllowlistContext(pub Cell<u8>);
impl crate::DestinationAllowlistVerificationContext for RejectingAllowlistContext {
    fn read_authority_state(&self) -> Result<crate::AuthorityStateSnapshot, AuthorityError> {
        Ok(state(5))
    }
    fn admit_or_recover_allowlist(
        &self,
        _: &crate::DestinationAllowlistAdmissionRequest,
    ) -> Result<crate::DurableAdmission, AuthorityError> {
        self.0.set(self.0.get() + 1);
        Err(AuthorityError::StaleOrRevokedPromotionBootstrap)
    }
}

fn new_admission<T: V5TestRequest>(request: &T) -> crate::DurableAdmission {
    crate::DurableAdmission::NewlyAdmitted {
        persisted: crate::PersistedAdmission {
            reservation: request.reservation().clone(),
            outcome: request.outcome().clone(),
        },
        state: request.newly_admitted_state().clone(),
    }
}

trait V5TestRequest {
    fn reservation(&self) -> &crate::ReservationIdentity;
    fn outcome(&self) -> &crate::OutcomeIdentity;
    fn newly_admitted_state(&self) -> &crate::AuthorityStateSnapshot;
}

macro_rules! test_request {
    ($type:ty) => {
        impl V5TestRequest for $type {
            fn reservation(&self) -> &crate::ReservationIdentity {
                &self.reservation
            }
            fn outcome(&self) -> &crate::OutcomeIdentity {
                &self.outcome
            }
            fn newly_admitted_state(&self) -> &crate::AuthorityStateSnapshot {
                &self.newly_admitted_state
            }
        }
    };
}
test_request!(crate::StageEnvelopeAdmissionRequest);
test_request!(crate::EvidenceEnvelopeAdmissionRequest);
test_request!(crate::DestinationAllowlistAdmissionRequest);

pub fn state(receipt_generation: u64) -> crate::AuthorityStateSnapshot {
    use ed25519_dalek::SigningKey;
    let root = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
    let mut role_scope_floors: Vec<_> = crate::V5_TRANSITION_ROLES
        .into_iter()
        .map(|role| crate::RoleScopeFloor {
            role: role.into(),
            scope: "transition".into(),
            revocation_epoch: 1,
        })
        .chain(
            crate::V5_EVIDENCE_ROLE_SCOPES
                .into_iter()
                .map(|(role, scope)| crate::RoleScopeFloor {
                    role: role.into(),
                    scope: scope.into(),
                    revocation_epoch: 1,
                }),
        )
        .collect();
    role_scope_floors.sort();
    crate::AuthorityStateSnapshot {
        durable_generation: 1,
        active_trust_generation: 4,
        active_receipt_generation: receipt_generation,
        active_allowlist_generation: 1,
        root: crate::RootAuthorityIdentity5D {
            principal_id: "rootprincipal".into(),
            controlling_account_id: "rootaccount".into(),
            lane_id: "rootlane".into(),
            key_id: crate::trust_canonical::hex(&crate::key_id(&root)),
            signature_profile_id: "rootprofile".into(),
            public_key: root,
            key_epoch: 4,
        },
        root_revocation_floor: 1,
        role_scope_floors,
    }
}
