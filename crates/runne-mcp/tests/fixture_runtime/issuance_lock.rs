#[test]
fn process_authority_hides_raw_boundary_and_issuance_retains_state_lock() {
    let runtime = include_str!("../../src/fixture/runtime.rs");
    let authority = runtime
        .split("impl FixtureProcessApprovalAuthority")
        .nth(1)
        .unwrap()
        .split("impl FixtureApprovalAuthority")
        .next()
        .unwrap();
    let publication = include_str!("../../src/fixture/publication.rs");

    assert!(!authority.contains("fn shared_boundary"));
    assert!(!authority.contains("-> Arc<"));
    assert!(!authority.contains("snapshot"));
    assert!(!authority.contains("reopen"));
    assert!(!authority.contains("validate"));
    assert_eq!(authority.matches("pub fn ").count(), 3);
    assert!(authority.contains("pub(super) fn compose_gateway"));
    assert!(publication.contains("struct PreparedIssue<'a>"));
    assert!(publication.contains("_state_guard: MutexGuard<'a, FixtureState>"));
    assert!(!publication.contains("drop(state)"));
}

#[test]
fn reconnect_fences_stale_protocol_and_process_issuance() {
    let mut protocol_runtime = runtime();
    initialize(&mut protocol_runtime);
    let protocol_publication = protocol_runtime.discover().unwrap();
    protocol_runtime
        .reconnect(McpConnectionId::new("connection-2").unwrap())
        .unwrap();
    assert!(matches!(
        protocol_publication.issue_dispatch("read", "stale-protocol", json!({"name":"ok"}), "p", "a", 2),
        Err(FixtureMcpFailure::DiscoveryStale)
    ));

    let mut process_runtime = process_runtime();
    initialize(&mut process_runtime);
    let process_publication = process_runtime.discover().unwrap();
    process_runtime
        .reconnect(McpConnectionId::new("connection-2").unwrap())
        .unwrap();
    assert!(matches!(
        process_publication.issue_dispatch(
            "read",
            "stale-process",
            json!({"name":"ok"}),
            "p",
            "a",
            2,
        ),
        Err(FixtureMcpFailure::DiscoveryStale)
    ));
}
