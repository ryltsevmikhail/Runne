use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use super::*;
use crate::{McpDispatchBinding, McpGenerationAdvanceError, McpGenerationAuthority};

fn next_binding(connection: &str, generation: u64, digest: [u8; 32]) -> McpDispatchBinding {
    McpDispatchBinding::new(
        McpServerId::new("fixture-server").unwrap(),
        McpRuntimeInstanceId::new("runtime-1").unwrap(),
        McpConnectionId::new(connection).unwrap(),
        McpSessionId::new("session-1").unwrap(),
        generation,
        digest,
    )
    .unwrap()
}

fn prepare_second_generation(
    runtime: &mut FixtureMcpRuntime,
) -> (FixturePublication, Arc<McpGenerationAuthority>) {
    initialize(runtime, "connection-1", 1);
    let first = runtime.discover().unwrap();
    let generation = runtime.process_generation_authority_for_test().unwrap();
    runtime
        .reconnect(McpConnectionId::new("connection-2").unwrap())
        .unwrap();
    initialize(runtime, "connection-2", 2);
    (first, generation)
}

#[test]
fn expected_generation_mismatch_rejects_discovery_without_mutating_authorization() {
    let (composition, intent, authority) = composition();
    let old = authority.bind_call(intent.lifecycle_binding()).unwrap();
    let mut runtime = runtime(composition);
    let (first, generation) = prepare_second_generation(&mut runtime);
    let drifted = next_binding("connection-2", 2, [9; 32]);
    generation.try_advance(&drifted).unwrap();
    runtime
        .reconnect(McpConnectionId::new("connection-3").unwrap())
        .unwrap();
    initialize(&mut runtime, "connection-3", 3);
    let target = next_binding("connection-3", 3, [9; 32]);
    assert!(generation.prepare_advance(&target).is_ok());

    assert!(matches!(
        runtime.discover(),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
    assert!(generation.claim_dispatch(&drifted).is_ok());
    assert!(matches!(
        generation.claim_dispatch(&first.binding),
        Err(McpGenerationClaimError::Stale)
    ));
    assert!(matches!(
        generation.claim_dispatch(&target),
        Err(McpGenerationClaimError::Stale)
    ));
    assert!(old.issue_capability(&intent, 20).is_ok());
    assert_eq!(
        runtime.process_composition_metadata().unwrap().generation(),
        Some(1)
    );
}

#[test]
fn max_revision_rejects_after_generation_prepare_without_mutating_state() {
    assert_authorization_overflow_preserves_cutover(u64::MAX, 1);
}

#[test]
fn max_epoch_rejects_after_generation_prepare_without_mutating_state() {
    assert_authorization_overflow_preserves_cutover(1, u64::MAX);
}

fn assert_authorization_overflow_preserves_cutover(revision: u64, epoch: u64) {
    let (composition, intent, authority) = composition_with(revision, epoch);
    let old = authority.bind_call(intent.lifecycle_binding()).unwrap();
    let mut runtime = runtime(composition);
    let (first, generation) = prepare_second_generation(&mut runtime);

    assert!(matches!(
        runtime.discover(),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
    assert!(generation.claim_dispatch(&first.binding).is_ok());
    assert!(old.issue_capability(&intent, 20).is_ok());
    assert_eq!(
        runtime.process_composition_metadata().unwrap().generation(),
        Some(1)
    );
}

#[test]
fn poisoned_generation_is_unavailable_without_changing_authorization_or_metadata() {
    let (composition, intent, authority) = composition();
    let old = authority.bind_call(intent.lifecycle_binding()).unwrap();
    let mut runtime = runtime(composition);
    let (_first, generation) = prepare_second_generation(&mut runtime);
    let prepared = generation
        .prepare_advance(&next_binding("connection-2", 2, [9; 32]))
        .unwrap();
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _prepared = prepared;
        panic!("poison generation guard");
    }));

    assert!(matches!(
        runtime.discover(),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
    assert!(matches!(
        generation.prepare_advance(&next_binding("connection-2", 2, [8; 32])),
        Err(McpGenerationAdvanceError::Unavailable)
    ));
    assert!(old.issue_capability(&intent, 20).is_ok());
    assert_eq!(
        runtime.process_composition_metadata().unwrap().generation(),
        Some(1)
    );
}

#[test]
fn poisoned_authorization_after_generation_prepare_preserves_generation_and_metadata() {
    let (composition, _intent, authority) = composition();
    let mut runtime = runtime(composition);
    let (first, generation) = prepare_second_generation(&mut runtime);
    let prepared = authority.prepare_advance().unwrap();
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _prepared = prepared;
        panic!("poison authorization guard");
    }));

    assert!(matches!(
        runtime.discover(),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
    assert!(generation.claim_dispatch(&first.binding).is_ok());
    assert_eq!(
        runtime.process_composition_metadata().unwrap().generation(),
        Some(1)
    );
}
