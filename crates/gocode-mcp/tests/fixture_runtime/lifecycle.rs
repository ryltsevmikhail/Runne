#[test]
fn fixture_protocol_response_completes_once() {
    let mut fixture = runtime();
    initialize(&mut fixture);
    let mut capability = fixture.discover().unwrap()
        .issue_dispatch("read", "once", json!({"name":"ok"}), "principal", "authority", 5).unwrap();
    assert_eq!(fixture.dispatch(&mut capability, None), Ok(FixtureCallResult::Completed));
    assert_eq!(fixture.dispatch(&mut capability, None), Ok(FixtureCallResult::Completed));
    assert_eq!(fixture.dispatch_count(), 1);
    assert_eq!(fixture.accounting_remaining(), 1);
    assert_eq!(fixture.audit().len(), 1);
}

#[test]
fn pre_dispatch_timeout_and_disconnect_send_nothing() {
    let script = FixtureScript::new(vec![FixtureStep::response_at(1, json!({})).unwrap()]).unwrap();
    let mut timeout = runtime_with(script, FixtureApprovalPolicy::FixtureDeterministicAllow, 1);
    initialize(&mut timeout);
    let mut capability = timeout.discover().unwrap()
        .issue_dispatch("read", "timeout", json!({"name":"ok"}), "p", "a", 2).unwrap();
    assert_eq!(timeout.dispatch(&mut capability, None), Err(FixtureMcpFailure::TimedOut));
    assert_eq!(timeout.dispatch_count(), 0);
    let script = FixtureScript::new(vec![FixtureStep::disconnect_before_dispatch_at(0)]).unwrap();
    let mut disconnect = runtime_with(script, FixtureApprovalPolicy::FixtureDeterministicAllow, 1);
    initialize(&mut disconnect);
    let mut capability = disconnect.discover().unwrap()
        .issue_dispatch("read", "disconnect", json!({"name":"ok"}), "p", "a", 2).unwrap();
    assert_eq!(disconnect.dispatch(&mut capability, None), Err(FixtureMcpFailure::TimedOut));
    assert_eq!(disconnect.dispatch_count(), 0);
}

#[test]
fn post_dispatch_timeout_disconnect_and_stale_response_are_uncertain_once() {
    for (name, step) in [
        ("timeout", FixtureStep::accepted_then_lost_at(0)),
        ("disconnect", FixtureStep::protocol_error_at(0)),
        ("stale", FixtureStep::stale_response_at(0)),
    ] {
        let script = FixtureScript::new(vec![step]).unwrap();
        let mut fixture = runtime_with(script, FixtureApprovalPolicy::FixtureDeterministicAllow, 1);
        initialize(&mut fixture);
        let mut capability = fixture.discover().unwrap()
            .issue_dispatch("read", name, json!({"name":"ok"}), "p", "a", 1).unwrap();
        assert_eq!(fixture.dispatch(&mut capability, None), Err(FixtureMcpFailure::DispatchUncertain));
        assert_eq!(fixture.dispatch(&mut capability, None), Err(FixtureMcpFailure::DispatchUncertain));
        assert_eq!(fixture.dispatch_count(), 1);
        assert_eq!(fixture.accounting_remaining(), 0);
        assert_eq!(fixture.audit().len(), 1);
    }
}

#[test]
fn approval_policies_and_reconnect_invalidate_old_authority() {
    let mut denied = runtime_with(response_script(), FixtureApprovalPolicy::AlwaysDeny, 1);
    initialize(&mut denied);
    let mut denied_capability = denied.discover().unwrap()
        .issue_dispatch("read", "deny", json!({"name":"ok"}), "p", "a", 1).unwrap();
    assert_eq!(denied.dispatch(&mut denied_capability, None), Err(FixtureMcpFailure::ApprovalRequired));
    assert_eq!(denied.dispatch_count(), 0);
    let (mut fixture, authority) = runtime_with_authority(
        response_script(),
        FixtureApprovalPolicy::ExplicitPerCall,
        1,
    );
    initialize(&mut fixture);
    let publication = fixture.discover().unwrap();
    let mut capability = publication.issue_dispatch("read", "approve", json!({"name":"ok"}), "p", "a", 1).unwrap();
    assert_eq!(fixture.dispatch(&mut capability, None), Err(FixtureMcpFailure::ApprovalMismatch));
    let approval = authority.approve(&capability).unwrap();
    assert_eq!(fixture.dispatch(&mut capability, Some(&approval)), Ok(FixtureCallResult::Completed));
    fixture.reconnect(McpConnectionId::new("connection-2").unwrap()).unwrap();
    assert!(matches!(publication.issue_dispatch("read", "stale", json!({"name":"ok"}), "p", "a", 2), Err(FixtureMcpFailure::DiscoveryStale)));
    assert!(matches!(fixture.discover(), Err(FixtureMcpFailure::InvalidStateTransition)));
}

#[test]
fn preapproved_exact_intent_requires_external_authority_and_rejects_changes() {
    let (mut fixture, authority) = runtime_with_authority(
        response_script(),
        FixtureApprovalPolicy::PreApprovedExactIntent,
        1,
    );
    initialize(&mut fixture);
    let publication = fixture.discover().unwrap();
    let mut approved = publication
        .issue_dispatch("read", "approved", json!({"name":"ok"}), "p", "a", 1)
        .unwrap();
    let approval = authority.approve(&approved).unwrap();
    let mut changed_input = publication
        .issue_dispatch("read", "approved", json!({"name":"changed"}), "p", "a", 1)
        .unwrap();
    assert_eq!(fixture.dispatch(&mut changed_input, Some(&approval)), Err(FixtureMcpFailure::ApprovalMismatch));
    assert_eq!(fixture.dispatch(&mut approved, Some(&approval)), Ok(FixtureCallResult::Completed));
    let mut changed_intent = publication
        .issue_dispatch("read", "changed-intent", json!({"name":"ok"}), "other", "a", 1)
        .unwrap();
    assert_eq!(fixture.dispatch(&mut changed_intent, Some(&approval)), Err(FixtureMcpFailure::ApprovalMismatch));

    let mut closed = runtime_with(response_script(), FixtureApprovalPolicy::PreApprovedExactIntent, 1);
    initialize(&mut closed);
    let mut capability = closed.discover().unwrap()
        .issue_dispatch("read", "no-authority", json!({"name":"ok"}), "p", "a", 1).unwrap();
    assert_eq!(closed.dispatch(&mut capability, None), Err(FixtureMcpFailure::ApprovalMismatch));
}

#[test]
fn disconnect_requires_fresh_reinitialize_and_foreign_approval_fails() {
    let script = FixtureScript::new(vec![FixtureStep::disconnect_before_dispatch_at(0)]).unwrap();
    let (mut fixture, authority) = runtime_with_authority(
        script,
        FixtureApprovalPolicy::ExplicitPerCall,
        1,
    );
    initialize(&mut fixture);
    let mut capability = fixture.discover().unwrap()
        .issue_dispatch("read", "disconnect-tombstone", json!({"name":"ok"}), "p", "a", 2).unwrap();
    let approval = authority.approve(&capability).unwrap();
    assert_eq!(fixture.dispatch(&mut capability, Some(&approval)), Err(FixtureMcpFailure::TimedOut));
    assert_eq!(fixture.dispatch(&mut capability, None), Err(FixtureMcpFailure::TimedOut));
    assert_eq!(fixture.dispatch_count(), 0);
    assert_eq!(fixture.accounting_remaining(), 1);
    assert!(fixture.audit().is_empty());
    assert_eq!(fixture.initialize(FixtureInitialize::new(
        McpRuntimeInstanceId::new("runtime-1").unwrap(), McpSessionId::new("session-1").unwrap(),
        McpConnectionId::new("connection-1").unwrap(), 2, "fixture-server", "1.0.0", "fixture-v1", "2025-11-25",
    )), Err(FixtureMcpFailure::ConnectionMismatch));
    fixture.initialize(FixtureInitialize::new(
        McpRuntimeInstanceId::new("runtime-1").unwrap(), McpSessionId::new("session-1").unwrap(),
        McpConnectionId::new("connection-2").unwrap(), 2, "fixture-server", "1.0.0", "fixture-v1", "2025-11-25",
    )).unwrap();
    assert!(fixture.discover().is_ok());
    let mut approved = runtime_with(response_script(), FixtureApprovalPolicy::ExplicitPerCall, 1);
    initialize(&mut approved);
    let capability = approved.discover().unwrap()
        .issue_dispatch("read", "foreign", json!({"name":"ok"}), "p", "a", 1).unwrap();
    let (mut foreign, foreign_authority) = runtime_with_authority(
        response_script(),
        FixtureApprovalPolicy::FixtureDeterministicAllow,
        2,
    );
    initialize(&mut foreign);
    assert_eq!(foreign_authority.approve(&capability), Err(FixtureMcpFailure::ApprovalMismatch));
}

#[test]
fn cancel_before_dispatch_exact_replay_is_cancelled_without_effect_or_accounting() {
    let script = FixtureScript::new(vec![FixtureStep::cancel_before_dispatch_at(0)]).unwrap();
    let mut fixture = runtime_with(script, FixtureApprovalPolicy::FixtureDeterministicAllow, 1);
    initialize(&mut fixture);
    let mut capability = fixture
        .discover()
        .unwrap()
        .issue_dispatch("read", "cancelled", json!({"name":"ok"}), "p", "a", 1)
        .unwrap();
    assert_eq!(fixture.dispatch(&mut capability, None), Err(FixtureMcpFailure::Cancelled));
    assert_eq!(fixture.dispatch(&mut capability, None), Err(FixtureMcpFailure::Cancelled));
    assert_eq!(fixture.dispatch_count(), 0);
    assert_eq!(fixture.accounting_remaining(), 1);
    assert!(fixture.audit().is_empty());
}

#[test]
fn accounting_denied_replay_preserves_the_next_scripted_response() {
    let script = FixtureScript::new(vec![
        FixtureStep::response_at(0, json!({})).unwrap(),
        FixtureStep::response_at(0, json!({})).unwrap(),
    ])
    .unwrap();
    let mut fixture = runtime_with(script, FixtureApprovalPolicy::FixtureDeterministicAllow, 1);
    initialize(&mut fixture);
    let publication = fixture.discover().unwrap();
    let mut consumed = publication
        .issue_dispatch("read", "consumed", json!({"name":"ok"}), "p", "a", 1)
        .unwrap();
    assert_eq!(fixture.dispatch(&mut consumed, None), Ok(FixtureCallResult::Completed));
    let mut denied = publication
        .issue_dispatch("read", "denied", json!({"name":"ok"}), "p", "a", 1)
        .unwrap();
    assert_eq!(fixture.dispatch(&mut denied, None), Err(FixtureMcpFailure::AccountingDenied));
    assert_eq!(fixture.dispatch(&mut denied, None), Err(FixtureMcpFailure::AccountingDenied));
    assert_eq!(fixture.dispatch_count(), 1);
    assert_eq!(fixture.accounting_remaining(), 0);
    assert_eq!(fixture.pending_script_steps(), 1);
}

#[test]
fn same_invocation_with_changed_input_or_binding_is_conflict_without_stale_result() {
    let script = FixtureScript::new(vec![
        FixtureStep::response_at(0, json!({})).unwrap(),
        FixtureStep::response_at(0, json!({})).unwrap(),
    ])
    .unwrap();
    let mut fixture = runtime_with(script, FixtureApprovalPolicy::FixtureDeterministicAllow, 2);
    initialize(&mut fixture);
    let publication = fixture.discover().unwrap();
    let mut completed = publication
        .issue_dispatch("read", "same", json!({"name":"ok"}), "p", "a", 1)
        .unwrap();
    let mut changed_input = publication
        .issue_dispatch("read", "same", json!({"name":"changed"}), "p", "a", 1)
        .unwrap();
    assert_eq!(fixture.dispatch(&mut completed, None), Ok(FixtureCallResult::Completed));
    assert_eq!(fixture.dispatch(&mut changed_input, None), Err(FixtureMcpFailure::InvocationConflict));
    fixture.reconnect(McpConnectionId::new("connection-2").unwrap()).unwrap();
    fixture.initialize(FixtureInitialize::new(
        McpRuntimeInstanceId::new("runtime-1").unwrap(), McpSessionId::new("session-1").unwrap(),
        McpConnectionId::new("connection-2").unwrap(), 2, "fixture-server", "1.0.0", "fixture-v1", "2025-11-25",
    )).unwrap();
    let mut changed_binding = fixture.discover().unwrap()
        .issue_dispatch("read", "same", json!({"name":"ok"}), "p", "a", 2).unwrap();
    assert_eq!(fixture.dispatch(&mut changed_binding, None), Err(FixtureMcpFailure::InvocationConflict));
    assert_eq!(fixture.dispatch_count(), 1);
    assert_eq!(fixture.accounting_remaining(), 1);
    assert_eq!(fixture.pending_script_steps(), 1);
}

#[test]
fn reconnect_rejects_stale_capability_without_dispatch_or_accounting() {
    let mut fixture = runtime();
    initialize(&mut fixture);
    let mut stale = fixture.discover().unwrap()
        .issue_dispatch("read", "stale-capability", json!({"name":"ok"}), "p", "a", 2).unwrap();
    fixture.reconnect(McpConnectionId::new("connection-2").unwrap()).unwrap();
    fixture.initialize(FixtureInitialize::new(
        McpRuntimeInstanceId::new("runtime-1").unwrap(), McpSessionId::new("session-1").unwrap(),
        McpConnectionId::new("connection-2").unwrap(), 2, "fixture-server", "1.0.0", "fixture-v1", "2025-11-25",
    )).unwrap();
    assert_eq!(fixture.dispatch(&mut stale, None), Err(FixtureMcpFailure::ConnectionMismatch));
    assert_eq!(fixture.dispatch_count(), 0);
    assert_eq!(fixture.accounting_remaining(), 2);
    assert!(fixture.audit().is_empty());
}

#[test]
fn reconnect_rejects_runtime_or_session_swap_while_retaining_expectation() {
    let mut fixture = runtime();
    initialize(&mut fixture);
    fixture.reconnect(McpConnectionId::new("connection-2").unwrap()).unwrap();
    let request = |runtime, session| FixtureInitialize::new(
        McpRuntimeInstanceId::new(runtime).unwrap(), McpSessionId::new(session).unwrap(),
        McpConnectionId::new("connection-2").unwrap(), 2, "fixture-server", "1.0.0", "fixture-v1", "2025-11-25",
    );
    assert_eq!(fixture.initialize(request("runtime-2", "session-1")), Err(FixtureMcpFailure::ServerIdentityMismatch));
    assert_eq!(fixture.initialize(request("runtime-1", "session-2")), Err(FixtureMcpFailure::SessionMismatch));
    assert!(matches!(fixture.discover(), Err(FixtureMcpFailure::InvalidStateTransition)));
    fixture.initialize(request("runtime-1", "session-1")).unwrap();
    assert!(fixture.discover().is_ok());
}
