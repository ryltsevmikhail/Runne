use runne_provider_deepseek::canary::{AccountingDisposition, TerminalUsage};

use super::{
    approvals::{
        PossibleDispatchBoundaryMint, mint_possible_dispatch_boundary, sealed as dispatch_sealed,
    },
    authority::{ApprovalReplayIdentity, ApprovalSet},
    fence::{Fence, FenceError, Observation, OfflineCanaryFence},
    report::{CanaryLifecycle, LifecycleDisposition},
    tests_authority::{approved_set, reserved_fence_with},
};

const PRICING: &str = "deepseek-v4-flash-0731-peak-offpeak-2026-08-16/1";

struct FakeDispatchBoundaryMint {
    foreign: bool,
}
impl dispatch_sealed::Sealed for FakeDispatchBoundaryMint {}
impl PossibleDispatchBoundaryMint for FakeDispatchBoundaryMint {
    fn mint_replay(&self, approvals: &ApprovalSet) -> ApprovalReplayIdentity {
        if self.foreign {
            ApprovalReplayIdentity([1; 32], [2; 32], 3, "x", "y", "z", 4, "w")
        } else {
            approvals.replay().clone()
        }
    }
}
fn mint(approvals: &ApprovalSet) -> super::approvals::PossibleDispatchBoundaryWitness {
    mint_possible_dispatch_boundary(approvals, &FakeDispatchBoundaryMint { foreign: false })
}
fn mint_foreign(approvals: &ApprovalSet) -> super::approvals::PossibleDispatchBoundaryWitness {
    mint_possible_dispatch_boundary(approvals, &FakeDispatchBoundaryMint { foreign: true })
}
pub(super) fn dispatching_fence() -> Fence {
    let approvals = approved_set();
    let witness = mint(&approvals);
    reserved_fence_with(approvals)
        .enter_dispatching(witness)
        .unwrap()
}

#[test]
fn enter_dispatching_consumes_approvals_and_reaches_dispatching() {
    let approvals = approved_set();
    let witness = mint(&approvals);
    let mut fence = reserved_fence_with(approvals)
        .enter_dispatching(witness)
        .unwrap();
    assert_eq!(fence.state(), OfflineCanaryFence::Dispatching);
    let mut lifecycle = CanaryLifecycle::default();
    lifecycle
        .observe_terminal_after_possible_dispatch(&mut fence)
        .unwrap();
    assert_eq!(fence.state(), OfflineCanaryFence::Terminal);
    assert!(matches!(
        lifecycle.disposition(),
        LifecycleDisposition::NotRun
    ));
}

#[test]
fn enter_dispatching_rejects_non_reserved_state_without_mutation() {
    let approvals = approved_set();
    let witness = mint(&approvals);
    assert!(matches!(
        Fence::armed(approved_set()).enter_dispatching(witness),
        Err(FenceError::InvalidTransition)
    ));
}

#[test]
fn replay_mismatch_rejects_without_consuming_approvals() {
    let approvals = approved_set();
    let foreign = mint_foreign(&approvals);
    assert!(matches!(
        reserved_fence_with(approvals).enter_dispatching(foreign),
        Err(FenceError::InvalidTransition)
    ));
    let fresh = approved_set();
    let witness = mint(&fresh);
    assert_eq!(
        reserved_fence_with(fresh)
            .enter_dispatching(witness)
            .unwrap()
            .state(),
        OfflineCanaryFence::Dispatching
    );
}

#[test]
fn observations_from_budget_reserved_are_invalid_transition() {
    let mut fence = reserved_fence_with(approved_set());
    assert!(matches!(
        fence.consume_terminal_observation(),
        Err(FenceError::InvalidTransition)
    ));
    assert!(matches!(
        fence.consume_uncertain_observation(),
        Err(FenceError::InvalidTransition)
    ));
    let outcome = fence.abort().unwrap();
    assert!(outcome.reservation_released() && outcome.approvals_unconsumed());
}

#[test]
fn abort_is_rejected_from_dispatching_terminal_and_uncertain() {
    let dispatching = dispatching_fence();
    assert!(matches!(
        dispatching.abort(),
        Err(FenceError::InvalidTransition)
    ));
    let mut terminal = dispatching_fence();
    CanaryLifecycle::default()
        .observe_terminal_after_possible_dispatch(&mut terminal)
        .unwrap();
    assert!(matches!(
        terminal.abort(),
        Err(FenceError::InvalidTransition)
    ));
    let mut uncertain = dispatching_fence();
    CanaryLifecycle::default()
        .observe_after_possible_dispatch(&mut uncertain, Observation::Cancelled)
        .unwrap();
    assert!(matches!(
        uncertain.abort(),
        Err(FenceError::InvalidTransition)
    ));
}

#[test]
fn witness_is_single_use_and_consumed_by_failed_entry() {
    let approvals = approved_set();
    let witness = mint(&approvals);
    assert!(matches!(
        Fence::armed(approved_set()).enter_dispatching(witness),
        Err(FenceError::InvalidTransition)
    ));
}

#[test]
fn happy_path_armed_to_dispatching_to_terminal_to_settlement() {
    let approvals = approved_set();
    let witness = mint(&approvals);
    let mut fence = Fence::armed(approvals)
        .credential_authorized()
        .unwrap()
        .network_authorized()
        .unwrap()
        .reserve_budget()
        .unwrap()
        .enter_dispatching(witness)
        .unwrap();
    assert_eq!(fence.state(), OfflineCanaryFence::Dispatching);
    let mut lifecycle = CanaryLifecycle::default();
    lifecycle
        .observe_terminal_after_possible_dispatch(&mut fence)
        .unwrap();
    let settled = lifecycle
        .reconcile(Some(TerminalUsage::new(256, 16, 0)), PRICING, 1_350)
        .unwrap();
    assert_eq!(settled.disposition(), AccountingDisposition::Reconciled);
    assert_eq!(lifecycle.disposition(), LifecycleDisposition::Terminal);
}
