#[test]
fn discovery_allowlist_publishes_only_selected_exact_tools() {
    let published = published();
    assert_eq!(published.snapshot().tool_refs().len(), 1);
    let tool_ref = &published.snapshot().tool_refs()[0];
    assert_eq!(tool_ref.tool_id().as_str(), "mcp::fixture-server::allowed");
    assert_eq!(
        published.resolve(tool_ref).unwrap().class(),
        ToolClass::McpRemote
    );
    assert!(
        published
            .snapshot()
            .tool_refs()
            .iter()
            .all(|reference| reference.tool_id().as_str() != "mcp::fixture-server::excluded")
    );
}

#[test]
fn local_and_remote_publications_bind_kind_to_digest_class_and_capability() {
    let descriptor = McpToolDescriptor::new("read", "1.0.0", json!({"type":"object"})).unwrap();
    let server_id = McpServerId::new("kind-server").unwrap();
    let local = publish_mcp_tools(server_id.clone(), McpServerKind::Local, vec![descriptor.clone()], &["read"]).unwrap();
    let equivalent_local = publish_mcp_tools(server_id.clone(), McpServerKind::Local, vec![descriptor.clone()], &["read"]).unwrap();
    let remote = publish_mcp_tools(server_id.clone(), McpServerKind::Remote, vec![descriptor], &["read"]).unwrap();
    let local_ref = local.snapshot().tool_refs()[0].clone();
    let remote_ref = remote.snapshot().tool_refs()[0].clone();
    assert_ne!(local.discovery_digest(), remote.discovery_digest());
    assert_eq!(local.discovery_digest(), equivalent_local.discovery_digest());
    assert_eq!(local.resolve(&local_ref).unwrap().class(), ToolClass::McpLocal);
    assert_eq!(local.resolve(&local_ref).unwrap().sandbox_profile(), SandboxProfile::McpLocal);
    assert_eq!(remote.resolve(&remote_ref).unwrap().class(), ToolClass::McpRemote);
    assert_eq!(remote.resolve(&remote_ref).unwrap().sandbox_profile(), SandboxProfile::NetworkRestricted);
    let binding = |digest| McpDispatchBinding::new(
        server_id.clone(),
        McpRuntimeInstanceId::new("runtime-1").unwrap(),
        McpConnectionId::new("connection-1").unwrap(),
        McpSessionId::new("session-1").unwrap(),
        1,
        digest,
    ).unwrap();
    let local_binding = binding(*local.discovery_digest());
    let remote_binding = binding(*remote.discovery_digest());
    assert!(matches!(
        local.issue_dispatch(&remote_binding, &local_ref, McpInvocationId::new("wrong-kind").unwrap(), json!({})),
        Err(McpDispatchCapabilityError::InvalidBinding)
    ));
    let local_capability = local.issue_dispatch(
        &local_binding,
        &local_ref,
        McpInvocationId::new("local-kind").unwrap(),
        json!({}),
    ).unwrap();
    let rejected = McpToolGateway::new(
        Admission { calls: Arc::new(Mutex::new(Vec::new())), reject: None },
        Client {
            sends: Arc::new(Mutex::new(0)),
            messages: Arc::new(Mutex::new(Vec::new())),
            fail_after_send: false,
            generation_cutover: None,
            reservations: reservations(),
        },
        Arc::new(McpGenerationAuthority::new(&remote_binding)),
        ToolOutputBounds::new(1024, 16, 16).unwrap(),
    );
    assert_eq!(rejected.dispatch(local_capability), Err(McpToolGatewayError::StaleGeneration));
}

#[test]
fn denied_stale_replay_and_post_send_uncertainty_are_mediated_by_gateway() {
    let published = published();
    let discovery_digest = *published.discovery_digest();
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let sends = Arc::new(Mutex::new(0));
    let messages = Arc::new(Mutex::new(Vec::new()));
    let active = binding(1, discovery_digest);
    let generation = Arc::new(McpGenerationAuthority::new(&active));
    let denied = McpToolGateway::new(
        Admission {
            calls: Arc::clone(&calls),
            reject: Some(GateStage::Budget),
        },
        Client {
            sends: Arc::clone(&sends),
            messages: Arc::clone(&messages),
            fail_after_send: false,
            generation_cutover: None,
            reservations: reservations(),
        },
        Arc::clone(&generation),
        ToolOutputBounds::new(1024, 16, 16).unwrap(),
    );
    let denied_capability = published
        .issue_dispatch(
            &active,
            &tool_ref,
            McpInvocationId::new("denied").unwrap(),
            json!({}),
        )
        .unwrap();
    assert!(denied.dispatch(denied_capability).is_err());
    assert_eq!(*sends.lock().unwrap(), 0);
    assert_eq!(
        *calls.lock().unwrap(),
        [
            GateStage::Capability,
            GateStage::Approval,
            GateStage::Budget
        ]
    );
    let wrong_connection = McpDispatchBinding::new(
        McpServerId::new("fixture-server").unwrap(),
        McpRuntimeInstanceId::new("runtime-1").unwrap(),
        McpConnectionId::new("connection-other").unwrap(),
        McpSessionId::new("session-1").unwrap(),
        1,
        discovery_digest,
    )
    .unwrap();
    let wrong_connection_capability = published
        .issue_dispatch(
            &wrong_connection,
            &tool_ref,
            McpInvocationId::new("wrong-connection").unwrap(),
            json!({}),
        )
        .unwrap();
    assert_eq!(
        denied.dispatch(wrong_connection_capability),
        Err(McpToolGatewayError::StaleGeneration)
    );
    assert_eq!(*sends.lock().unwrap(), 0);

    let stale_sends = Arc::new(Mutex::new(0));
    let stale_messages = Arc::new(Mutex::new(Vec::new()));
    let stale = McpToolGateway::new(
        Admission {
            calls: Arc::new(Mutex::new(Vec::new())),
            reject: None,
        },
        Client {
            sends: Arc::clone(&stale_sends),
            messages: stale_messages,
            fail_after_send: false,
            generation_cutover: None,
            reservations: reservations(),
        },
        Arc::new(McpGenerationAuthority::new(&binding(2, discovery_digest))),
        ToolOutputBounds::new(1024, 16, 16).unwrap(),
    );
    let stale_capability = published
        .issue_dispatch(
            &active,
            &tool_ref,
            McpInvocationId::new("stale").unwrap(),
            json!({}),
        )
        .unwrap();
    assert_eq!(
        stale.dispatch(stale_capability),
        Err(McpToolGatewayError::StaleGeneration)
    );
    assert_eq!(*stale_sends.lock().unwrap(), 0);

    let uncertain_sends = Arc::new(Mutex::new(0));
    let uncertain_calls = Arc::new(Mutex::new(Vec::new()));
    let uncertain_messages = Arc::new(Mutex::new(Vec::new()));
    let guarded_generation = Arc::new(McpGenerationAuthority::new(&active));
    let next_binding = binding(2, discovery_digest);
    let uncertain = McpToolGateway::new(
        Admission {
            calls: Arc::clone(&uncertain_calls),
            reject: None,
        },
        Client {
            sends: Arc::clone(&uncertain_sends),
            messages: Arc::clone(&uncertain_messages),
            fail_after_send: true,
            generation_cutover: Some((Arc::clone(&guarded_generation), next_binding.clone())),
            reservations: reservations(),
        },
        Arc::clone(&guarded_generation),
        ToolOutputBounds::new(1024, 16, 16).unwrap(),
    );
    let uncertain_capability = published
        .issue_dispatch(
            &active,
            &tool_ref,
            McpInvocationId::new("uncertain").unwrap(),
            json!({"x": 1}),
        )
        .unwrap();
    assert_eq!(
        uncertain.dispatch(uncertain_capability),
        Err(McpToolGatewayError::Gateway(
            ToolGatewayError::UncertainAfterAdmission
        ))
    );
    let replay_capability = published
        .issue_dispatch(
            &active,
            &tool_ref,
            McpInvocationId::new("uncertain").unwrap(),
            json!({"x": 1}),
        )
        .unwrap();
    assert_eq!(
        uncertain.dispatch(replay_capability),
        Err(McpToolGatewayError::Gateway(
            ToolGatewayError::UncertainAfterAdmission
        ))
    );
    assert_eq!(
        uncertain_messages.lock().unwrap()[0].params().unwrap()["name"],
        "allowed"
    );
    assert_eq!(*uncertain_sends.lock().unwrap(), 1);
    assert_eq!(
        *uncertain_calls.lock().unwrap(),
        [
            GateStage::Capability,
            GateStage::Approval,
            GateStage::Budget,
            GateStage::Containment,
            GateStage::EffectAdmission,
        ]
    );
    assert_eq!(
        uncertain.dispatch(
            published
                .issue_dispatch(
                    &active,
                    &tool_ref,
                    McpInvocationId::new("uncertain").unwrap(),
                    json!({"x": 2}),
                )
                .unwrap(),
        ),
        Err(McpToolGatewayError::Gateway(
            ToolGatewayError::DigestConflict
        ))
    );
    assert_eq!(*uncertain_sends.lock().unwrap(), 1);
    assert_eq!(guarded_generation.try_advance(&next_binding), Ok(()));
}
