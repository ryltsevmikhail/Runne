use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

use super::{
    authority::{
        ApprovalError, ApprovalTransactionAuthority, AuthorityBindings, ClaimBundle,
        EvaluationTime, approve, sealed,
    },
    fence::{EffectDisposition, Fence, FenceError, OfflineCanaryFence},
    report::{CanaryLifecycle, LifecycleDisposition},
    tests_dispatch::dispatching_fence,
};
use gocode_provider_deepseek::canary::{CanaryCandidate, CanaryIdentity, CanaryOverlay};

fn candidate() -> CanaryCandidate {
    CanaryCandidate::prepare(CanaryIdentity::canonical(), CanaryOverlay::approved()).unwrap()
}
fn bindings() -> AuthorityBindings {
    AuthorityBindings::for_candidate(&candidate())
}
struct FakeApprovalAuthority {
    bundle: Option<ClaimBundle>,
    realm: Rc<RefCell<BTreeSet<super::authority::ApprovalReplayIdentity>>>,
    consumes: u8,
}
impl FakeApprovalAuthority {
    fn new(bindings: AuthorityBindings) -> Self {
        Self::in_realm(bindings, Rc::default())
    }
    fn in_realm(
        bindings: AuthorityBindings,
        realm: Rc<RefCell<BTreeSet<super::authority::ApprovalReplayIdentity>>>,
    ) -> Self {
        Self {
            bundle: Some(ClaimBundle::fake(bindings)),
            realm,
            consumes: 0,
        }
    }
    fn missing(mut self, claim: u8) -> Self {
        self.bundle.as_mut().unwrap().remove(claim);
        self
    }
    fn mutate(&mut self, claim: u8, apply: fn(&mut AuthorityBindings)) {
        apply(self.bundle.as_mut().unwrap().bindings_mut(claim));
    }
    fn pending_complete(&self) -> bool {
        self.bundle.as_ref().is_some_and(ClaimBundle::is_complete)
    }
}
impl sealed::Sealed for FakeApprovalAuthority {}
impl ApprovalTransactionAuthority for FakeApprovalAuthority {
    fn preview(&self) -> Result<super::authority::ApprovalTransaction<'_>, ApprovalError> {
        self.bundle
            .as_ref()
            .map(|bundle| super::authority::ApprovalTransaction::from(Some(bundle)))
            .ok_or(ApprovalError::AlreadyClaimed)
    }
    fn consume_all(
        &mut self,
        ticket: super::authority::ValidatedApprovalTransaction,
    ) -> Result<ClaimBundle, ApprovalError> {
        if !ticket.matches(self.bundle.as_ref()) || self.realm.borrow().contains(ticket.identity())
        {
            return Err(ApprovalError::AlreadyClaimed);
        }
        self.realm.borrow_mut().insert(ticket.into_identity());
        self.consumes += 1;
        self.bundle.take().ok_or(ApprovalError::AlreadyClaimed)
    }
}
impl core::fmt::Debug for FakeApprovalAuthority {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ExternalAuthority")
    }
}
fn approve_fake(
    expected: &AuthorityBindings,
    authority: &mut FakeApprovalAuthority,
) -> Result<super::authority::ApprovalSet, ApprovalError> {
    approve(expected, EvaluationTime::new(15), authority)
}
fn assert_closed_time_refusal(mutate: fn(&mut super::authority::AuthorityBindings)) {
    for claim in 0..3 {
        let expected = bindings();
        let mut authority = FakeApprovalAuthority::new(expected.clone());
        authority.mutate(claim, mutate);
        assert_eq!(
            approve_fake(&expected, &mut authority).unwrap_err(),
            ApprovalError::InvalidTime
        );
        assert!(authority.pending_complete() && authority.consumes == 0);
    }
}
pub(super) fn approved_set() -> super::authority::ApprovalSet {
    let bindings = bindings();
    approve_fake(&bindings, &mut FakeApprovalAuthority::new(bindings.clone())).unwrap()
}
pub(super) fn reserved_fence_with(approvals: super::authority::ApprovalSet) -> Fence {
    Fence::armed(approvals)
        .credential_authorized()
        .unwrap()
        .network_authorized()
        .unwrap()
        .reserve_budget()
        .unwrap()
}
pub(super) fn reserved_fence() -> Fence {
    reserved_fence_with(approved_set())
}
fn assert_invalid<T: core::fmt::Debug>(result: Result<T, FenceError>) {
    assert_eq!(result.unwrap_err(), FenceError::InvalidTransition);
}

#[test]
fn late_network_or_cost_failure_keeps_complete_bundle_pending() {
    for claim in [1, 2] {
        let expected = bindings();
        let mut authority = FakeApprovalAuthority::new(expected.clone());
        authority.mutate(claim, AuthorityBindings::mismatch_path);
        assert_eq!(
            approve_fake(&expected, &mut authority).unwrap_err(),
            ApprovalError::BindingMismatch
        );
        assert!(authority.pending_complete());
        assert_eq!(authority.consumes, 0);
    }
}

#[test]
fn missing_claim_leaves_pending_bundle_intact() {
    for (claim, error) in [
        (0, ApprovalError::MissingCredential),
        (1, ApprovalError::MissingNetwork),
        (2, ApprovalError::MissingCost),
    ] {
        let expected = bindings();
        let mut authority = FakeApprovalAuthority::new(expected.clone()).missing(claim);
        assert_eq!(approve_fake(&expected, &mut authority).unwrap_err(), error);
        assert!(authority.bundle.is_some());
        assert_eq!(authority.consumes, 0);
    }
}

#[test]
fn success_consumes_all_claims_exactly_once() {
    let expected = bindings();
    let mut authority = FakeApprovalAuthority::new(expected.clone());
    let approvals = approve_fake(&expected, &mut authority).unwrap();
    assert!(authority.bundle.is_none() && authority.consumes == 1);
    assert_eq!(
        approve_fake(&expected, &mut authority).unwrap_err(),
        ApprovalError::AlreadyClaimed
    );
    assert_eq!(authority.consumes, 1);
    let _ = approvals;
}

#[test]
fn shared_realm_replay_rejects_second_bundle_without_consuming_it() {
    let expected = bindings();
    let realm = Rc::<RefCell<BTreeSet<super::authority::ApprovalReplayIdentity>>>::default();
    let mut first = FakeApprovalAuthority::in_realm(expected.clone(), realm.clone());
    let mut second = FakeApprovalAuthority::in_realm(expected.clone(), realm);
    approve_fake(&expected, &mut first).unwrap();
    assert_eq!(
        approve_fake(&expected, &mut second).unwrap_err(),
        ApprovalError::AlreadyClaimed
    );
    assert!(second.pending_complete() && second.consumes == 0);
}

#[test]
fn single_use_and_claim_id_mismatches_fail_before_consume() {
    for claim in 0..3 {
        for mutate in [
            AuthorityBindings::disable_single_use,
            AuthorityBindings::mismatch_claim_id,
        ] {
            let expected = bindings();
            let mut authority = FakeApprovalAuthority::new(expected.clone());
            authority.mutate(claim, mutate);
            assert_eq!(
                approve_fake(&expected, &mut authority).unwrap_err(),
                ApprovalError::BindingMismatch
            );
            assert!(authority.pending_complete() && authority.consumes == 0);
        }
    }
}

#[test]
fn pre_dispatch_abort_returns_actual_approvals_for_rearming() {
    let outcome = reserved_fence().abort().unwrap();
    assert_eq!(outcome.fence(), OfflineCanaryFence::Aborted);
    assert_eq!(
        outcome.disposition(),
        EffectDisposition::DefinitelyNotDispatched
    );
    assert!(outcome.reservation_released() && outcome.approvals_unconsumed());
    let rearmed = Fence::armed(outcome.into_approvals().expect("approvals are returned"));
    assert_eq!(rearmed.state(), OfflineCanaryFence::Armed);
}

#[test]
fn invalid_abort_states_remain_rejected() {
    let mut terminal = dispatching_fence();
    CanaryLifecycle::default()
        .observe_terminal_after_possible_dispatch(&mut terminal)
        .unwrap();
    assert_invalid(terminal.abort());
    let mut uncertain = dispatching_fence();
    CanaryLifecycle::default()
        .observe_after_possible_dispatch(&mut uncertain, super::fence::Observation::Cancelled)
        .unwrap();
    assert_invalid(uncertain.abort());
}

#[test]
fn fence_transitions_and_observation_still_require_reservation() {
    assert_eq!(Fence::default().state(), OfflineCanaryFence::Disarmed);
    assert_invalid(Fence::default().credential_authorized());
    assert_invalid(Fence::armed(approved_set()).network_authorized());
    let mut lifecycle = CanaryLifecycle::default();
    let mut fence = Fence::armed(approved_set());
    assert_eq!(
        lifecycle.observe_terminal_after_possible_dispatch(&mut fence),
        Err(FenceError::InvalidTransition)
    );
    assert_eq!(lifecycle.disposition(), LifecycleDisposition::NotRun);
}

pub(super) fn rendered_authority_fence_types() -> String {
    let mut expected = bindings();
    expected.raw_sentinel();
    let mut authority = FakeApprovalAuthority::new(expected.clone());
    let preview = format!("{:?}", authority.preview().unwrap());
    let approvals = approve_fake(&expected, &mut authority).unwrap();
    let abort = reserved_fence_with(approvals).abort().unwrap();
    format!(
        "{preview}{authority:?}{abort:?}{:?}{:?}{:?}",
        Fence::default(),
        ApprovalError::AlreadyClaimed,
        EffectDisposition::DefinitelyNotDispatched
    )
}

#[test]
fn debug_remains_redacted() {
    let rendered = rendered_authority_fence_types();
    for raw in [
        "principal-raw",
        "authority-raw",
        "session-raw",
        "9",
        "handle",
    ] {
        assert!(!rendered.contains(raw));
    }
}

#[test]
fn clock_rollback_is_closed_refusal() {
    assert_closed_time_refusal(AuthorityBindings::clock_rolled_back);
}
#[test]
fn zero_ttl_is_closed_refusal() {
    assert_closed_time_refusal(AuthorityBindings::zero_ttl);
}
#[test]
fn expiry_boundary_is_closed_refusal() {
    assert_closed_time_refusal(AuthorityBindings::expired_at_boundary);
}
#[test]
fn cost_cap_over_is_closed_refusal() {
    let expected = bindings();
    let mut authority = FakeApprovalAuthority::new(expected.clone());
    authority.mutate(2, AuthorityBindings::cost_cap_over);
    assert_eq!(
        approve_fake(&expected, &mut authority).unwrap_err(),
        ApprovalError::CostCapExceeded
    );
    assert!(authority.pending_complete() && authority.consumes == 0);
}
