mod stale;
pub(in crate::fixture) mod support;

use crate::discovery::ProcessCallBindingError;

use super::super::{
    FixtureApprovalPolicy, FixtureAuditProcessReason, FixtureCallResult, FixtureMcpFailure,
};
use support::*;

const ROUTING_CASES: [&str; 12] = [
    "registry_has_exact_cardinality",
    "missing_composition_rejects_before_reservation",
    "l1_rejection_preserves_payload_without_reservation",
    "c2b_mismatch_rejects_before_reservation",
    "stale_connection_rejects_before_replay",
    "stale_generation_rejects_before_replay",
    "production_probe_refunds_and_restores_payload",
    "accounting_rejects_before_payload_move",
    "qualified_probe_admits_then_is_sticky_uncertain",
    "fresh_capability_replays_terminal_without_redispatch",
    "process_dispatch_does_not_consume_script_step",
    "protocol_dispatch_remains_unchanged",
];

#[test]
fn registry_has_exact_cardinality() {
    assert_eq!(ROUTING_CASES.len(), 12);
}

#[test]
fn missing_composition_rejects_before_reservation() {
    let mut fixture =
        ready_without_composition(1, FixtureApprovalPolicy::FixtureDeterministicAllow);
    let mut capability = fixture.issue("missing-composition");

    assert_eq!(
        fixture.runtime.dispatch(&mut capability, None),
        Err(FixtureMcpFailure::ProcessSandboxUnavailable)
    );
    assert_eq!(fixture.runtime.accounting_remaining(), 1);
    assert!(capability.take_process_payload().is_some());
}

#[test]
fn l1_rejection_preserves_payload_without_reservation() {
    let mut fixture = ready(Probe::Qualified, 1, FixtureApprovalPolicy::AlwaysDeny);
    let mut capability = fixture.issue("l1-reject");

    assert_eq!(
        fixture.runtime.dispatch(&mut capability, None),
        Err(FixtureMcpFailure::ApprovalRequired)
    );
    assert_eq!(fixture.runtime.accounting_remaining(), 1);
    assert!(capability.take_process_payload().is_some());
}

#[test]
fn c2b_mismatch_rejects_before_reservation() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut capability = fixture.issue("c2b-match");
    let payload = capability.take_process_payload().unwrap();
    let mismatch = fixture.intent("c2b-mismatch");

    assert!(matches!(
        payload.mcp().verify_c2b(&mismatch),
        Err(ProcessCallBindingError::ProcessIntentMismatch)
    ));
    assert_eq!(fixture.runtime.accounting_remaining(), 1);
}

#[test]
fn production_probe_refunds_and_restores_payload() {
    let mut fixture = ready(
        Probe::Production,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut capability = fixture.issue("production-probe");

    for _ in 0..2 {
        assert_eq!(
            fixture.runtime.dispatch(&mut capability, None),
            Err(FixtureMcpFailure::ProcessSandboxUnavailable)
        );
        assert_eq!(fixture.runtime.accounting_remaining(), 1);
        assert!(capability.take_process_payload().is_some());
        capability.restore_process_payload(
            fixture
                .issue("production-probe")
                .take_process_payload()
                .unwrap(),
        );
    }
}

#[test]
fn accounting_rejects_before_payload_move() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut first = fixture.issue("held-accounting");
    let mut denied = fixture.issue("accounting-denied");

    assert_eq!(
        fixture.runtime.dispatch(&mut first, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    assert_eq!(
        fixture.runtime.dispatch(&mut denied, None),
        Err(FixtureMcpFailure::AccountingDenied)
    );
    assert_eq!(denied.process_payload_take_count_for_test(), 0);
    assert!(denied.take_process_payload().is_some());
}

#[test]
fn qualified_probe_admits_then_is_sticky_uncertain() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut capability = fixture.issue("qualified-state");

    assert_eq!(
        fixture.runtime.dispatch(&mut capability, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    assert_eq!(fixture.runtime.accounting_remaining(), 0);
    assert!(capability.take_process_payload().is_none());
    assert_eq!(
        fixture.runtime.process_effect_admission_count_for_test(),
        Some(1)
    );
    assert_eq!(
        fixture
            .runtime
            .try_audit()
            .unwrap()
            .last()
            .unwrap()
            .process_reason(),
        Some(FixtureAuditProcessReason::Denied)
    );
    assert_eq!(
        process_phases(&fixture.runtime),
        [
            super::super::FixtureAuditProcessPhase::Reserved,
            super::super::FixtureAuditProcessPhase::Admitted,
            super::super::FixtureAuditProcessPhase::Uncertain
        ]
    );
}

#[test]
fn fresh_capability_replays_terminal_without_redispatch() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut first = fixture.issue("terminal-replay");
    let mut replay = fixture.issue("terminal-replay");

    assert_eq!(
        fixture.runtime.dispatch(&mut first, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    assert_eq!(
        fixture.runtime.dispatch(&mut replay, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    assert_eq!(
        fixture.runtime.process_effect_admission_count_for_test(),
        Some(1)
    );
}

#[test]
fn process_dispatch_does_not_consume_script_step() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut capability = fixture.issue("process-script");

    assert_eq!(fixture.runtime.pending_script_steps(), 1);
    assert_eq!(
        fixture.runtime.dispatch(&mut capability, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    assert_eq!(fixture.runtime.pending_script_steps(), 1);
}

#[test]
fn protocol_dispatch_remains_unchanged() {
    assert_protocol_process_invocation_conflicts();
    let (mut runtime, approval, mut capability) = protocol_fixture();

    assert_eq!(
        runtime.dispatch(&mut capability, Some(&approval)),
        Ok(FixtureCallResult::Completed)
    );
    assert_eq!(runtime.pending_script_steps(), 0);
    assert_eq!(runtime.dispatch_count(), 1);
}
