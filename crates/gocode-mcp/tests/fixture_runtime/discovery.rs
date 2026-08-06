#[test]
fn exact_read_lookup_does_not_confuse_bread_suffix() {
    let bread = FixtureTool::new(
        "bread",
        "1.0.0",
        "safe bread",
        json!({"type":"object","properties":{"crumb":{"type":"string"}},"required":["crumb"],"additionalProperties":false}),
        json!({"type":"object","additionalProperties":false}),
    )
    .unwrap();
    let read = read_tool(json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}));
    let mut fixture = runtime_with_definition(
        vec![bread, read],
        response_script(),
        &["bread", "read"],
        FixtureApprovalPolicy::FixtureDeterministicAllow,
        1,
    );
    initialize(&mut fixture);
    let mut capability = fixture
        .discover()
        .unwrap()
        .issue_dispatch("read", "exact-read", json!({"name":"ok"}), "p", "a", 1)
        .unwrap();
    assert_eq!(fixture.dispatch(&mut capability, None), Ok(FixtureCallResult::Completed));
    assert_eq!(fixture.dispatch_count(), 1);
}

#[test]
fn definition_digest_is_config_bound_and_capabilities_are_issuer_bound() {
    let mut source = runtime();
    let equivalent = runtime();
    assert_eq!(source.definition_digest(), equivalent.definition_digest());
    assert_ne!(
        source.definition_digest(),
        runtime_with(response_script(), FixtureApprovalPolicy::AlwaysDeny, 2).definition_digest()
    );
    assert_ne!(
        source.definition_digest(),
        runtime_with_definition(
            vec![read_tool(json!({"type":"object","properties":{"title":{"type":"string"}},"required":["title"],"additionalProperties":false}))],
            response_script(),
            &["read"],
            FixtureApprovalPolicy::FixtureDeterministicAllow,
            2,
        )
        .definition_digest()
    );
    assert_ne!(
        source.definition_digest(),
        runtime_with(response_script(), FixtureApprovalPolicy::FixtureDeterministicAllow, 3)
            .definition_digest()
    );

    initialize(&mut source);
    let mut foreign = source
        .discover()
        .unwrap()
        .issue_dispatch("read", "issuer", json!({"name":"ok"}), "p", "a", 1)
        .unwrap();
    let mut denied = runtime_with(response_script(), FixtureApprovalPolicy::AlwaysDeny, 2);
    initialize(&mut denied);
    assert_eq!(denied.dispatch(&mut foreign, None), Err(FixtureMcpFailure::CapabilityMissing));
    let mut local = denied
        .discover()
        .unwrap()
        .issue_dispatch("read", "denied", json!({"name":"ok"}), "p", "a", 1)
        .unwrap();
    assert_eq!(denied.dispatch(&mut local, None), Err(FixtureMcpFailure::ApprovalRequired));

    let output = FixtureTool::new(
        "read",
        "1.0.0",
        "safe read",
        json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}),
        json!({"type":"string"}),
    )
    .unwrap();
    let mut destination = runtime_with_definition(
        vec![output],
        response_script(),
        &["read"],
        FixtureApprovalPolicy::FixtureDeterministicAllow,
        1,
    );
    initialize(&mut destination);
    let mut local = destination
        .discover()
        .unwrap()
        .issue_dispatch("read", "output", json!({"name":"ok"}), "p", "a", 1)
        .unwrap();
    assert_eq!(destination.dispatch(&mut local, None), Err(FixtureMcpFailure::OutputSchemaMismatch));
}

#[test]
fn nonadjacent_duplicate_required_names_are_rejected() {
    assert!(matches!(
        FixtureTool::new(
            "read",
            "1.0.0",
            "safe read",
            json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b","a"],"additionalProperties":false}),
            json!({"type":"object","additionalProperties":false}),
        ),
        Err(FixtureMcpFailure::ToolDefinitionInvalid)
    ));
}
