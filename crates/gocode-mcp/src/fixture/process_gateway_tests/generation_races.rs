use std::sync::mpsc;
use std::thread;

use super::super::FixtureApprovalPolicy;
use super::super::runtime_process_tests::routing::support::*;
use crate::McpGenerationAdvanceError;

#[test]
fn generation_lease_blocks_cutover_through_settlement_then_fresh_discovery_succeeds() {
    let fixture = ready(
        Probe::Qualified,
        1,
        FixtureApprovalPolicy::FixtureDeterministicAllow,
    );
    let binding = fixture
        .issue("generation-race")
        .take_process_payload()
        .unwrap()
        .mcp()
        .verified_process_call()
        .0;
    let generation = fixture
        .runtime
        .process_generation_authority_for_test()
        .unwrap();
    let next = crate::McpDispatchBinding::new(
        binding.server_id().clone(),
        crate::McpRuntimeInstanceId::new("runtime-1").unwrap(),
        crate::McpConnectionId::new(binding.connection_id()).unwrap(),
        crate::McpSessionId::new("session-1").unwrap(),
        binding.generation() + 1,
        [9; 32],
    )
    .unwrap();
    let (settled_sender, settled_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let (key, payload) = key_payload(&fixture, "generation-race");
    fixture
        .runtime
        .pause_process_gateway_after_settlement_for_test(settled_sender, release_receiver);

    let worker = thread::spawn(move || {
        assert!(matches!(
            fixture
                .runtime
                .dispatch_process_gateway_for_test(key, payload),
            Ok(super::super::runtime::process_ledger::ProcessPhaseOutcome::EffectUncertain { .. })
        ));
        fixture
    });
    settled_receiver.recv().unwrap();
    assert!(matches!(
        generation.prepare_advance(&next),
        Err(McpGenerationAdvanceError::Busy)
    ));
    release_sender.send(()).unwrap();
    let mut fixture = worker.join().unwrap();
    assert_eq!(process_phases(&fixture.runtime).len(), 3);
    reconnect(&mut fixture.runtime, "connection-2", 2);
    assert!(fixture.runtime.discover().is_ok());
}
