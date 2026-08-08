fn process_tool() -> FixtureTool {
    FixtureTool::new_process_backed(
        "read",
        "1.0.0",
        "safe read",
        json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}),
        json!({"type":"object","additionalProperties":false}),
    )
    .unwrap()
}

fn process_runtime() -> FixtureMcpRuntime {
    runtime_with_definition(
        vec![process_tool()],
        response_script(),
        &["read"],
        FixtureApprovalPolicy::FixtureDeterministicAllow,
        1,
    )
}

#[test]
fn fixture_tool_execution_class_changes_definition_and_discovery_behavior() {
    let protocol = read_tool(json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}));
    let protocol_runtime = runtime_with_definition(
        vec![protocol],
        response_script(),
        &["read"],
        FixtureApprovalPolicy::FixtureDeterministicAllow,
        1,
    );
    let process_runtime = process_runtime();

    assert_ne!(protocol_runtime.definition_digest(), process_runtime.definition_digest());

    let mut protocol_runtime = protocol_runtime;
    initialize(&mut protocol_runtime);
    assert!(protocol_runtime
        .discover()
        .unwrap()
        .issue_dispatch("read", "protocol", json!({"name":"ok"}), "p", "a", 1)
        .is_ok());

    let mut process_runtime = process_runtime;
    initialize(&mut process_runtime);
    assert!(matches!(
        process_runtime
            .discover()
            .unwrap()
            .issue_dispatch("read", "process", json!({"name":"ok"}), "p", "a", 1),
        Err(FixtureMcpFailure::ProcessIntentRequired)
    ));
}

#[test]
fn ordinary_process_issue_has_no_fixture_side_effects() {
    let mut fixture = process_runtime();
    initialize(&mut fixture);
    let publication = fixture.discover().unwrap();

    assert!(matches!(
        publication.issue_dispatch("read", "ordinary", json!({"name":"ok"}), "p", "a", 1),
        Err(FixtureMcpFailure::ProcessIntentRequired)
    ));
    assert_eq!(fixture.dispatch_count(), 0);
    assert_eq!(fixture.accounting_remaining(), 1);
    assert_eq!(fixture.pending_script_steps(), 1);
}
