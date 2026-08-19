use crate::fixture::{FixtureApprovalPolicy, FixtureMcpFailure};

use super::support::*;

#[test]
fn stale_connection_rejects_before_replay() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut first = fixture.issue("stale-connection");
    let mut replay = fixture.issue("stale-connection");
    let mut stale = fixture.issue("stale-connection");
    assert_eq!(
        fixture.runtime.dispatch(&mut first, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    let before_replay =
        super::super::super::runtime::process_ledger::terminal_replay_count_for_test();
    assert_eq!(
        fixture.runtime.dispatch(&mut replay, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    assert_eq!(
        super::super::super::runtime::process_ledger::terminal_replay_count_for_test(),
        before_replay + 1
    );
    assert_eq!(
        fixture.runtime.process_effect_admission_count_for_test(),
        Some(1)
    );
    reconnect(&mut fixture.runtime, "connection-2", 2);
    fixture.runtime.discover().unwrap();

    assert_eq!(
        fixture.runtime.dispatch(&mut stale, None),
        Err(FixtureMcpFailure::GenerationMismatch)
    );
    assert_eq!(fixture.runtime.accounting_remaining(), 0);
    assert!(stale.take_process_payload().is_some());
    assert_eq!(
        super::super::super::runtime::process_ledger::terminal_replay_count_for_test(),
        before_replay + 1
    );
    assert_eq!(
        fixture.runtime.process_effect_admission_count_for_test(),
        Some(1)
    );
}

#[test]
fn stale_generation_rejects_before_replay() {
    let mut fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let mut first = fixture.issue("stale-generation");
    let mut replay = fixture.issue("stale-generation");
    let mut stale = fixture.issue("stale-generation");
    assert_eq!(
        fixture.runtime.dispatch(&mut first, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    let before_replay =
        super::super::super::runtime::process_ledger::terminal_replay_count_for_test();
    assert_eq!(
        fixture.runtime.dispatch(&mut replay, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    assert_eq!(
        super::super::super::runtime::process_ledger::terminal_replay_count_for_test(),
        before_replay + 1
    );
    reconnect(&mut fixture.runtime, "connection-2", 2);
    let fresh = fixture.runtime.discover().unwrap();
    let generation = fixture
        .runtime
        .process_generation_authority_for_test()
        .unwrap();

    assert!(generation.claim_dispatch(&fresh.binding).is_ok());
    assert_eq!(
        fixture.runtime.dispatch(&mut stale, None),
        Err(FixtureMcpFailure::GenerationMismatch)
    );
    assert_eq!(fixture.runtime.accounting_remaining(), 0);
    assert_eq!(
        super::super::super::runtime::process_ledger::terminal_replay_count_for_test(),
        before_replay + 1
    );
    assert_eq!(
        fixture.runtime.process_effect_admission_count_for_test(),
        Some(1)
    );
}
