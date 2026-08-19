use super::super::runtime::process_ledger::{ProcessPhaseOutcome, ProcessUncertainReason};
use super::super::runtime_process_tests::routing::support::*;
use super::super::{FixtureApprovalPolicy, FixtureMcpFailure};

#[test]
fn budget_fault_returns_verified_payload_and_refunds_once() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let payload = budget_denied_dispatch(&fixture, "gateway-budget");

    assert!(
        payload
            .mcp()
            .verify_c2b(payload.material().intent())
            .is_ok()
    );
    assert_eq!(fixture.runtime.accounting_remaining(), 1);
}

#[test]
fn actual_dispatch_records_witness_before_uncertain_terminal_state() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut capability = fixture.issue("gateway-witness");

    assert_eq!(
        fixture.runtime.dispatch(&mut capability, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    assert_eq!(process_phases(&fixture.runtime).len(), 3);
    assert_eq!(
        fixture.runtime.process_effect_admission_count_for_test(),
        Some(1)
    );
}

#[test]
fn uncertain_after_admission_is_state_and_replay_does_not_redispatch() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let gateway = effect_uncertain_gateway(
        &fixture,
        super::super::process_gateway::ProcessGateFault::EffectUncertain,
    );
    let (key, payload) = key_payload(&fixture, "gateway-state");

    assert!(matches!(
        gateway
            .dispatch_for_test(&fixture.runtime, key, payload)
            .unwrap(),
        ProcessPhaseOutcome::EffectUncertain {
            reason: ProcessUncertainReason::State,
            ..
        }
    ));
    let (key, replay) = key_payload(&fixture, "gateway-state");
    assert!(matches!(
        gateway.dispatch_for_test(&fixture.runtime, key, replay),
        Err(super::super::process_gateway::ledger_port::TestDispatchError::TerminalReplay)
    ));
    assert_eq!(gateway.effect_admission_count(), 1);
    assert_eq!(
        process_phases(&fixture.runtime),
        [
            super::super::FixtureAuditProcessPhase::Reserved,
            super::super::FixtureAuditProcessPhase::Admitted,
            super::super::FixtureAuditProcessPhase::Uncertain,
        ]
    );
}

#[test]
fn test_dispatch_helper_classifies_terminal_replay_without_effect() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let (key, payload) = key_payload(&fixture, "gateway-terminal");
    fixture
        .runtime
        .dispatch_process_gateway_for_test(key.clone(), payload)
        .unwrap();
    let (_, replay) = key_payload(&fixture, "gateway-terminal");

    assert!(matches!(
        fixture
            .runtime
            .dispatch_process_gateway_for_test(key, replay),
        Err(super::super::process_gateway::ledger_port::TestDispatchError::TerminalReplay)
    ));
    assert_eq!(
        fixture.runtime.process_effect_admission_count_for_test(),
        Some(1)
    );
}
