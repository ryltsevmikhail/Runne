use super::*;
use crate::{McpConnectionId, McpRuntimeInstanceId, McpServerId, McpSessionId};

fn binding(generation: u64) -> McpDispatchBinding {
    McpDispatchBinding::new(
        McpServerId::new("fixture-server").unwrap(),
        McpRuntimeInstanceId::new("runtime-1").unwrap(),
        McpConnectionId::new("connection-1").unwrap(),
        McpSessionId::new("session-1").unwrap(),
        generation,
        [generation as u8; 32],
    )
    .unwrap()
}

#[test]
fn prepared_generation_drop_leaves_the_current_generation_unchanged() {
    let first = binding(1);
    let authority = McpGenerationAuthority::new(&first);
    let prepared = authority.prepare_advance(&binding(2)).unwrap();

    assert_eq!(prepared.current_generation(), 1);
    drop(prepared);

    assert!(authority.claim_dispatch(&first).is_ok());
}

#[test]
fn retaining_generation_apply_is_idempotent_and_try_advance_stays_compatible() {
    let first = binding(1);
    let second = binding(2);
    let authority = McpGenerationAuthority::new(&first);
    let mut prepared = authority.prepare_advance(&second).unwrap();

    prepared.apply_retaining_lock();
    prepared.apply_retaining_lock();
    assert_eq!(prepared.current_generation(), 2);
    drop(prepared);
    assert_eq!(authority.try_advance(&binding(3)), Ok(()));
    assert_eq!(
        authority.try_advance(&second),
        Err(McpGenerationAdvanceError::InvalidGeneration)
    );
}
