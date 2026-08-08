use std::panic::{AssertUnwindSafe, catch_unwind};

use super::super::process_gateway::ProcessGateFault;
use super::super::runtime::process_ledger::ProcessUncertainReason;
use super::super::{FixtureApprovalPolicy, FixtureMcpFailure};
use super::routing::support::*;
use crate::McpConnectionId;

const RECOVERY_CASES: [&str; 14] = [
    "registry_has_exact_cardinality",
    "reconnect_reuses_gateway_without_redispatch",
    "denied_is_sticky_without_redispatch",
    "state_is_sticky_without_redispatch",
    "host_is_sticky_without_redispatch",
    "pending_is_sticky_without_redispatch",
    "cleanup_is_sticky_without_redispatch",
    "executor_is_sticky_without_redispatch",
    "lifecycle_is_sticky_without_redispatch",
    "ledger_is_sticky_without_redispatch",
    "final_validation_panic_poison_fence",
    "witness_assignment_panic_poison_fence",
    "commit_panic_poison_fence",
    "poison_fence_rejects_later_runtime_calls",
];

#[test]
fn registry_has_exact_cardinality() {
    assert_eq!(RECOVERY_CASES.len(), 14);
}

#[test]
fn reconnect_reuses_gateway_without_redispatch() {
    let mut fixture = ready(
        Probe::Qualified,
        2,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut first = fixture.issue("reconnect");
    assert_eq!(
        fixture.runtime.dispatch(&mut first, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    let effect_admissions = fixture.runtime.process_effect_admission_count_for_test();
    let host_dispatches = fixture.runtime.process_host_dispatch_count_for_test();
    let terminal_audit_count = process_phases(&fixture.runtime)
        .into_iter()
        .filter(|phase| {
            matches!(
                phase,
                super::super::FixtureAuditProcessPhase::Completed
                    | super::super::FixtureAuditProcessPhase::Uncertain
            )
        })
        .count();
    reconnect(&mut fixture.runtime, "connection-2", 2);
    let publication = fixture.runtime.discover().unwrap();
    let mut fresh = fixture.issue_from(&publication, "reconnect");
    let audit_len = fixture.runtime.try_audit().unwrap().len();

    assert_eq!(
        fixture.runtime.dispatch(&mut fresh, None),
        Err(FixtureMcpFailure::InvocationConflict)
    );
    assert_eq!(fixture.runtime.try_audit().unwrap().len(), audit_len);
    assert_eq!(
        fixture.runtime.process_effect_admission_count_for_test(),
        effect_admissions
    );
    assert_eq!(
        fixture.runtime.process_host_dispatch_count_for_test(),
        host_dispatches
    );
    assert_eq!(
        process_phases(&fixture.runtime)
            .into_iter()
            .filter(|phase| {
                matches!(
                    phase,
                    super::super::FixtureAuditProcessPhase::Completed
                        | super::super::FixtureAuditProcessPhase::Uncertain
                )
            })
            .count(),
        terminal_audit_count
    );
    assert_eq!(
        fixture
            .runtime
            .process_composition_metadata()
            .unwrap()
            .host_compositions(),
        1
    );
}

macro_rules! ordinary_case {
    ($name:ident, $reason:expr) => {
        #[test]
        fn $name() {
            assert_sticky_ordinary($reason);
        }
    };
}

ordinary_case!(
    denied_is_sticky_without_redispatch,
    ProcessUncertainReason::Denied
);
ordinary_case!(
    state_is_sticky_without_redispatch,
    ProcessUncertainReason::State
);
ordinary_case!(
    host_is_sticky_without_redispatch,
    ProcessUncertainReason::Host
);
ordinary_case!(
    pending_is_sticky_without_redispatch,
    ProcessUncertainReason::Pending
);
ordinary_case!(
    cleanup_is_sticky_without_redispatch,
    ProcessUncertainReason::Cleanup
);
ordinary_case!(
    executor_is_sticky_without_redispatch,
    ProcessUncertainReason::Executor
);
ordinary_case!(
    lifecycle_is_sticky_without_redispatch,
    ProcessUncertainReason::Lifecycle
);
ordinary_case!(
    ledger_is_sticky_without_redispatch,
    ProcessUncertainReason::Ledger
);

#[test]
fn final_validation_panic_poison_fence() {
    assert_panic_poison(ProcessGateFault::PanicFinalValidation);
}

#[test]
fn witness_assignment_panic_poison_fence() {
    assert_panic_poison(ProcessGateFault::PanicWitnessAssignment);
}

#[test]
fn commit_panic_poison_fence() {
    assert_panic_poison(ProcessGateFault::PanicCommit);
}

#[test]
fn poison_fence_rejects_later_runtime_calls() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let gateway = effect_uncertain_gateway(&fixture, ProcessGateFault::PanicCommit);
    let mut later_capability = fixture.issue("poison-runtime-dispatch");
    let (key, payload) = key_payload(&fixture, "poison-fence");
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            gateway
                .dispatch_for_test(&fixture.runtime, key, payload)
                .unwrap();
        }))
        .is_err()
    );
    assert_eq!(
        fixture.runtime.try_audit(),
        Err(FixtureMcpFailure::InvalidStateTransition)
    );
    assert!(catch_unwind(AssertUnwindSafe(|| fixture.runtime.audit())).is_err());
    assert!(matches!(
        fixture.runtime.discover(),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
    assert_eq!(
        fixture.runtime.dispatch(&mut later_capability, None),
        Err(FixtureMcpFailure::InvalidStateTransition)
    );
    assert_eq!(
        fixture.runtime.advance_clock(1),
        Err(FixtureMcpFailure::InvalidStateTransition)
    );
    assert_eq!(
        fixture
            .runtime
            .reconnect(McpConnectionId::new("connection-2").unwrap()),
        Err(FixtureMcpFailure::InvalidStateTransition)
    );
}

fn assert_sticky_ordinary(reason: ProcessUncertainReason) {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let gateway = effect_uncertain_gateway(&fixture, ProcessGateFault::Uncertain(reason));
    let (key, payload) = key_payload(&fixture, "sticky-ordinary");
    assert!(matches!(
        gateway.dispatch_for_test(&fixture.runtime, key.clone(), payload),
        Ok(super::super::runtime::process_ledger::ProcessPhaseOutcome::EffectUncertain {
            reason: actual,
            ..
        }) if actual == reason
    ));
    let audit_len = fixture.runtime.try_audit().unwrap().len();
    let host_count = gateway.host_dispatch_count_for_test();
    let (_, replay) = key_payload(&fixture, "sticky-ordinary");
    assert!(matches!(
        gateway.dispatch_for_test(&fixture.runtime, key, replay),
        Err(super::super::process_gateway::ledger_port::TestDispatchError::TerminalReplay)
    ));
    assert_eq!(gateway.effect_admission_count(), 1);
    assert_eq!(gateway.host_dispatch_count_for_test(), host_count);
    assert_eq!(fixture.runtime.accounting_remaining(), 0);
    assert_eq!(fixture.runtime.try_audit().unwrap().len(), audit_len);
}

fn assert_panic_poison(fault: ProcessGateFault) {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let gateway = effect_uncertain_gateway(&fixture, fault);
    let (key, payload) = key_payload(&fixture, "panic-poison");
    let retry_key = key.clone();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            gateway
                .dispatch_for_test(&fixture.runtime, key, payload)
                .unwrap();
        }))
        .is_err()
    );
    assert_eq!(gateway.effect_admission_count(), 0);
    assert_eq!(gateway.host_dispatch_count_for_test(), 0);
    assert_eq!(fixture.runtime.accounting_remaining(), 0);
    assert!(matches!(
        fixture.runtime.reserve_process(retry_key),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
    assert_eq!(
        fixture.runtime.try_audit(),
        Err(FixtureMcpFailure::InvalidStateTransition)
    );
}
