use std::sync::{Arc, Barrier, mpsc};
use std::thread;

use super::super::{
    FixtureApprovalPolicy, FixtureAuditProcessPhase, FixtureAuditProcessReason, FixtureMcpFailure,
};
use super::routing::support::*;
use crate::{McpGenerationAdvanceError, McpGenerationClaimError};

mod audit;
mod permits;
mod protocol;
mod support;

use support::next_binding;

const GATEWAY_CASES: [&str; 16] = [
    "registry_has_exact_cardinality",
    "permit_is_full_lowercase_digest",
    "permit_changes_with_capability_material",
    "budget_denial_returns_boxed_payload_after_single_refund",
    "budget_denial_keeps_outer_payload_usable",
    "dispatch_for_test_reaches_admitted_then_uncertain",
    "host_denial_is_audited_as_uncertain",
    "c2b_mismatch_does_not_create_a_ledger_entry",
    "terminal_replay_is_classified_without_redispatch",
    "generation_read_permit_blocks_advance",
    "generation_read_permit_rejects_stale_binding",
    "fresh_terminal_replay_keeps_one_effect_admission",
    "process_dispatch_keeps_script_immutable",
    "qualified_dispatch_keeps_accounting_held",
    "reentrant_containment_probe_releases_fixture_state",
    "protocol_dispatch_behavior_remains_available",
];

#[test]
fn registry_has_exact_cardinality() {
    assert_eq!(GATEWAY_CASES.len(), 16);
}

#[test]
fn budget_denial_returns_boxed_payload_after_single_refund() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let payload = budget_denied_dispatch(&fixture, "budget-boxed");

    assert!(
        payload
            .mcp()
            .verify_c2b(payload.material().intent())
            .is_ok()
    );
    assert_eq!(fixture.runtime.accounting_remaining(), 1);
}

#[test]
fn budget_denial_keeps_outer_payload_usable() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let payload = budget_denied_dispatch(&fixture, "budget-retry");
    let key = fixture.issue("budget-retry").process_key().unwrap().clone();

    assert!(
        fixture
            .runtime
            .dispatch_process_gateway_for_test(key, payload)
            .is_ok()
    );
}

#[test]
fn dispatch_for_test_reaches_admitted_then_uncertain() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let (key, payload) = key_payload(&fixture, "gateway-dispatch");

    assert!(matches!(
        fixture
            .runtime
            .dispatch_process_gateway_for_test(key, payload),
        Ok(super::super::runtime::process_ledger::ProcessPhaseOutcome::EffectUncertain { .. })
    ));
    assert_eq!(
        fixture.runtime.process_effect_admission_count_for_test(),
        Some(1)
    );
}

#[test]
fn host_denial_is_audited_as_uncertain() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut capability = fixture.issue("host-denial");

    assert_eq!(
        fixture.runtime.dispatch(&mut capability, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    let terminal = fixture.runtime.try_audit().unwrap().pop().unwrap();
    assert_eq!(
        terminal.process_phase(),
        Some(FixtureAuditProcessPhase::Uncertain)
    );
    assert_eq!(
        terminal.process_reason(),
        Some(FixtureAuditProcessReason::Denied)
    );
}

#[test]
fn c2b_mismatch_does_not_create_a_ledger_entry() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let (key, payload) = key_payload(&fixture, "c2b-ledger");

    assert!(
        payload
            .mcp()
            .verify_c2b(&fixture.intent("other-call"))
            .is_err()
    );
    assert!(matches!(
        fixture.runtime.reserve_process(key),
        Ok(super::super::runtime::process_ledger::ProcessReserveOutcome::Owner(_))
    ));
}

#[test]
fn terminal_replay_is_classified_without_redispatch() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let (key, payload) = key_payload(&fixture, "helper-replay");
    fixture
        .runtime
        .dispatch_process_gateway_for_test(key.clone(), payload)
        .unwrap();
    let (_, replay) = key_payload(&fixture, "helper-replay");

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

#[test]
fn generation_read_permit_blocks_advance() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let generation = fixture
        .runtime
        .process_generation_authority_for_test()
        .unwrap();
    let binding = fixture
        .issue("generation-hold")
        .take_process_payload()
        .unwrap()
        .mcp()
        .verified_process_call()
        .0;
    let next = next_binding(&binding);
    let barrier = Arc::new(Barrier::new(2));
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let holder_generation = Arc::clone(&generation);
    let holder_binding = binding.clone();
    let holder_barrier = Arc::clone(&barrier);
    let holder = thread::spawn(move || {
        let permit = holder_generation.claim_dispatch(&holder_binding).unwrap();
        ready_sender.send(()).unwrap();
        holder_barrier.wait();
        release_receiver.recv().unwrap();
        drop(permit);
    });

    ready_receiver.recv().unwrap();
    assert!(matches!(
        generation.prepare_advance(&next),
        Err(McpGenerationAdvanceError::Busy)
    ));
    barrier.wait();
    release_sender.send(()).unwrap();
    holder.join().unwrap();
    assert!(generation.prepare_advance(&next).is_ok());
}

#[test]
fn generation_read_permit_rejects_stale_binding() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let stale = fixture
        .issue("generation-stale")
        .take_process_payload()
        .unwrap()
        .mcp()
        .verified_process_call()
        .0;
    reconnect(&mut fixture.runtime, "connection-2", 2);
    let fresh = fixture.runtime.discover().unwrap();
    let generation = fixture
        .runtime
        .process_generation_authority_for_test()
        .unwrap();

    assert!(generation.claim_dispatch(&fresh.binding).is_ok());
    assert!(matches!(
        generation.claim_dispatch(&stale),
        Err(McpGenerationClaimError::Stale)
    ));
}

#[test]
fn fresh_terminal_replay_keeps_one_effect_admission() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut first = fixture.issue("fresh-replay");
    let mut replay = fixture.issue("fresh-replay");
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
fn process_dispatch_keeps_script_immutable() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut capability = fixture.issue("script-stable");
    fixture.runtime.dispatch(&mut capability, None).unwrap_err();
    assert_eq!(fixture.runtime.pending_script_steps(), 1);
}

#[test]
fn qualified_dispatch_keeps_accounting_held() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut capability = fixture.issue("accounting-held");
    fixture.runtime.dispatch(&mut capability, None).unwrap_err();
    assert_eq!(fixture.runtime.accounting_remaining(), 0);
}
