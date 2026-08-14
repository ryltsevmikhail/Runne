//! Regression tests for durable stage-envelope admission recovery.

use std::cell::{Cell, RefCell};

use crate::{
    AuthorityError, StageVerificationContext,
    receipt_v4::{test_empty_subject, verified_bootstrap},
};
#[derive(Clone, Eq, PartialEq)]
struct Scope(
    crate::PromotionBootstrapAdmissionScope,
    [u8; 32],
    String,
    [u8; 32],
    String,
    [u8; 32],
);
struct AtomicContext {
    clock: Cell<u64>,
    floor: Cell<u64>,
    root_epoch: Cell<u64>,
    claim: RefCell<Option<(Scope, u64)>>,
    race_floor: Cell<bool>,
}
impl AtomicContext {
    const fn new() -> Self {
        Self {
            clock: Cell::new(1),
            floor: Cell::new(1),
            root_epoch: Cell::new(0),
            claim: RefCell::new(None),
            race_floor: Cell::new(false),
        }
    }
}
impl crate::StageVerificationContext for AtomicContext {
    fn admit_or_recover(
        &self,
        request: &crate::StageAdmissionRequest<'_>,
    ) -> Result<crate::StageAdmission, AuthorityError> {
        let scope = Scope(
            request.bootstrap_admission_scope.clone(),
            request.scope.bootstrap_receipt_sha256,
            request.scope.role.into(),
            request.scope.payload_sha256,
            request.scope.authorization_nonce.into(),
            request.scope.envelope_sha256,
        );
        let floor = self.floor.get();
        if request.bootstrap_admission_scope.root_revocation_epoch() != self.root_epoch.get()
            || request.envelope_revocation_epoch != request.payload_revocation_epoch
            || request.envelope_revocation_epoch < floor
        {
            return Err(AuthorityError::StaleOrRevokedStageEnvelope);
        }
        if let Some((existing, admitted_floor)) = self.claim.borrow().as_ref() {
            return if existing == &scope && *admitted_floor == floor {
                Ok(crate::StageAdmission::ExistingSame)
            } else if existing.2 == scope.2 && existing.4 == scope.4 {
                Err(AuthorityError::ReplayedStageEnvelope)
            } else {
                Err(AuthorityError::StaleOrRevokedStageEnvelope)
            };
        }
        if self.race_floor.replace(false) {
            self.floor.set(floor + 1);
        }
        if self.floor.get() != floor
            || self.clock.get() < request.payload_valid_from
            || self.clock.get() >= request.payload_expires_at
        {
            return Err(AuthorityError::StaleOrRevokedStageEnvelope);
        }
        self.claim.borrow_mut().replace((scope, floor));
        Ok(crate::StageAdmission::NewlyAdmitted)
    }
}

fn request<'a>(
    bootstrap_handle: &'a crate::VerifiedPromotionBootstrap,
    bootstrap: u8,
    payload: u8,
    envelope: u8,
    nonce: &'static str,
) -> crate::StageAdmissionRequest<'a> {
    let reservation = Box::leak(Box::new(
        gocode_promotion_contracts::StageTransitionReservation::new(
            "promotion".into(),
            1,
            "command".into(),
            gocode_promotion_contracts::CanonicalPayloadKind::Rc1Decision,
            [7; 32],
        )
        .expect("fixture reservation"),
    ));
    crate::StageAdmissionRequest {
        bootstrap_validity: bootstrap_handle.validity(),
        bootstrap_admission_scope: bootstrap_handle.admission_scope(),
        scope: crate::StageAdmissionScope {
            reservation,
            bootstrap_receipt_sha256: [bootstrap; 32],
            role: "RC1_QUALIFICATION_AUTHORIZER",
            payload_sha256: [payload; 32],
            authorization_nonce: nonce,
            envelope_sha256: [envelope; 32],
        },
        envelope_not_before: "2026-08-13T00:00:00Z",
        envelope_expires_at: "2026-08-13T00:00:02Z",
        envelope_revocation_epoch: 1,
        payload_valid_from: 1,
        payload_expires_at: 2,
        payload_revocation_epoch: 1,
    }
}

#[test]
fn atomic_admission_recovers_only_exact_unchanged_scope() {
    let context = AtomicContext::new();
    let bootstrap = test_bootstrap(1);
    let first = request(&bootstrap, 1, 2, 3, "nonce");
    assert_eq!(
        context.admit_or_recover(&first),
        Ok(crate::StageAdmission::NewlyAdmitted)
    );
    context.clock.set(9);
    assert_eq!(
        context.admit_or_recover(&first),
        Ok(crate::StageAdmission::ExistingSame)
    );
    assert_eq!(
        context.admit_or_recover(&request(&bootstrap, 1, 2, 4, "nonce")),
        Err(AuthorityError::ReplayedStageEnvelope)
    );
    assert_eq!(
        context.admit_or_recover(&request(&bootstrap, 9, 2, 3, "nonce")),
        Err(AuthorityError::ReplayedStageEnvelope)
    );
}

#[test]
fn atomic_admission_rejects_revocation_change_and_race() {
    let context = AtomicContext::new();
    let bootstrap = test_bootstrap(1);
    let first = request(&bootstrap, 1, 2, 3, "nonce");
    assert_eq!(
        context.admit_or_recover(&first),
        Ok(crate::StageAdmission::NewlyAdmitted)
    );
    context.floor.set(2);
    assert_eq!(
        context.admit_or_recover(&first),
        Err(AuthorityError::StaleOrRevokedStageEnvelope)
    );
    let root_revoked = AtomicContext::new();
    assert_eq!(
        root_revoked.admit_or_recover(&first),
        Ok(crate::StageAdmission::NewlyAdmitted)
    );
    root_revoked.root_epoch.set(1);
    assert_eq!(
        root_revoked.admit_or_recover(&first),
        Err(AuthorityError::StaleOrRevokedStageEnvelope)
    );
    let race = AtomicContext::new();
    race.race_floor.set(true);
    assert_eq!(
        race.admit_or_recover(&first),
        Err(AuthorityError::StaleOrRevokedStageEnvelope)
    );
}

#[test]
fn atomic_admission_rejects_new_stale_and_inner_mismatch() {
    let context = AtomicContext::new();
    let bootstrap = test_bootstrap(1);
    context.clock.set(2);
    assert_eq!(
        context.admit_or_recover(&request(&bootstrap, 1, 2, 3, "nonce")),
        Err(AuthorityError::StaleOrRevokedStageEnvelope)
    );
    let mismatch = crate::StageAdmissionRequest {
        payload_revocation_epoch: 2,
        ..request(&bootstrap, 1, 2, 3, "nonce")
    };
    assert_eq!(
        AtomicContext::new().admit_or_recover(&mismatch),
        Err(AuthorityError::StaleOrRevokedStageEnvelope)
    );
}

fn test_bootstrap(digest: u8) -> crate::VerifiedPromotionBootstrap {
    verified_bootstrap(
        [digest; 32],
        Vec::new(),
        [9; 32],
        test_empty_subject(),
        String::new(),
    )
}
