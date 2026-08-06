#[test]
fn schemas_tool_definitions_and_bounds_fail_closed_before_dispatch() {
    assert!(matches!(FixtureTool::new("bad", "1.0.0", "bad", json!({"$ref":"forbidden"}), json!({"type":"null"})), Err(FixtureMcpFailure::ToolDefinitionInvalid)));
    let tool = FixtureTool::new("read", "1.0.0", "safe", json!({"type":"null"}), json!({"type":"null"})).unwrap();
    let identity = FixtureIdentity::new(McpServerId::new("fixture-server").unwrap(), "1.0.0", "fixture-v1", "2025-11-25").unwrap();
    let script = FixtureScript::new(vec![FixtureStep::response_at(0, json!(null)).unwrap()]).unwrap();
    assert!(matches!(FixtureMcpRuntime::new(FixtureMcpMode::FixtureOnly, identity.clone(), vec![tool.clone(), tool.clone()], script.clone(), &["read"], FixtureLimits::default(), FixtureApprovalPolicy::FixtureDeterministicAllow, 1), Err(FixtureMcpFailure::ToolDefinitionInvalid)));
    assert!(matches!(FixtureMcpRuntime::new(FixtureMcpMode::FixtureOnly, identity, vec![tool], script, &["outside"], FixtureLimits::default(), FixtureApprovalPolicy::FixtureDeterministicAllow, 1), Err(FixtureMcpFailure::ToolDefinitionInvalid)));
    let mut fixture = runtime();
    initialize(&mut fixture);
    let publication = fixture.discover().unwrap();
    let nested = (0..10).fold(json!("ok"), |value, _| json!([value]));
    assert!(matches!(publication.issue_dispatch("read", "depth", nested, "p", "a", 1), Err(FixtureMcpFailure::RequestTooLarge)));
    assert!(matches!(publication.issue_dispatch("read", "bytes", json!({"name":"x".repeat(20_000)}), "p", "a", 1), Err(FixtureMcpFailure::RequestTooLarge)));
    assert!(matches!(publication.issue_dispatch("read", "unknown", json!({"name":"ok","extra":true}), "p", "a", 1), Err(FixtureMcpFailure::InputSchemaMismatch)));
    assert_eq!(fixture.dispatch_count(), 0);
}

#[test]
fn invalid_result_and_response_bound_are_typed_and_cannot_retry() {
    assert!(matches!(FixtureStep::response_at(0, json!("x".repeat(20_000))), Err(FixtureMcpFailure::ResponseTooLarge)));
    let script = FixtureScript::new(vec![FixtureStep::response_at(0, json!("wrong")).unwrap()]).unwrap();
    let mut fixture = runtime_with(script, FixtureApprovalPolicy::FixtureDeterministicAllow, 1);
    initialize(&mut fixture);
    let mut capability = fixture.discover().unwrap()
        .issue_dispatch("read", "result", json!({"name":"ok"}), "p", "a", 1).unwrap();
    assert_eq!(fixture.dispatch(&mut capability, None), Err(FixtureMcpFailure::OutputSchemaMismatch));
    assert_eq!(fixture.dispatch_count(), 1);
    assert_eq!(fixture.dispatch(&mut capability, None), Err(FixtureMcpFailure::DispatchUncertain));
    assert_eq!(fixture.accounting_remaining(), 0);
}

#[test]
fn accounting_mismatch_is_consumed_once_and_replay_is_fenced() {
    let script = FixtureScript::new(vec![FixtureStep::accounting_mismatch_at(0)]).unwrap();
    let mut fixture = runtime_with(script, FixtureApprovalPolicy::FixtureDeterministicAllow, 1);
    initialize(&mut fixture);
    let mut capability = fixture.discover().unwrap()
        .issue_dispatch("read", "mismatch", json!({"name":"ok"}), "p", "a", 1).unwrap();
    assert_eq!(fixture.dispatch(&mut capability, None), Err(FixtureMcpFailure::AccountingMismatch));
    assert_eq!(fixture.accounting_remaining(), 0);
    assert_eq!(fixture.dispatch(&mut capability, None), Err(FixtureMcpFailure::DispatchUncertain));
    assert_eq!(fixture.dispatch_count(), 1);
}

#[test]
fn schema_subset_enforces_constraints_and_rejects_unknown_keywords() {
    let schema = json!({"type":"object","properties":{"name":{"type":"string","enum":["ok"],"minLength":2,"maxLength":2},"count":{"type":"integer","minimum":1,"maximum":2}},"required":["name","count"],"additionalProperties":false});
    let tool = FixtureTool::new("read", "1.0.0", "safe", schema.clone(), schema).unwrap();
    let identity = FixtureIdentity::new(McpServerId::new("fixture-server").unwrap(), "1.0.0", "fixture-v1", "2025-11-25").unwrap();
    let script = FixtureScript::new(vec![FixtureStep::response_at(0, json!({"name":"ok","count":1})).unwrap()]).unwrap();
    let mut fixture = FixtureMcpRuntime::new(FixtureMcpMode::FixtureOnly, identity, vec![tool], script, &["read"], FixtureLimits::default(), FixtureApprovalPolicy::FixtureDeterministicAllow, 1).unwrap();
    initialize(&mut fixture);
    let publication = fixture.discover().unwrap();
    for input in [json!({"name":"no","count":1}), json!({"name":"ok","count":0}), json!({"name":"ok","count":3})] {
        assert!(matches!(
            publication.issue_dispatch("read", "constraints", input, "p", "a", 1),
            Err(FixtureMcpFailure::InputSchemaMismatch)
        ));
    }
    assert!(matches!(FixtureTool::new("bad", "1.0.0", "bad", json!({"type":"array","items":{"type":"string"},"maxItems":1}), json!({"type":"null"})), Err(FixtureMcpFailure::ToolDefinitionInvalid)));
    assert!(matches!(FixtureTool::new("bad", "1.0.0", "bad", json!({"type":"array"}), json!({"type":"null"})), Err(FixtureMcpFailure::ToolDefinitionInvalid)));
}
