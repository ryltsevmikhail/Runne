#[test]
fn local_and_remote_publications_bind_kind_to_digest_class_and_capability() {
    let descriptor = McpToolDescriptor::new_with_execution_class(
        "read",
        "1.0.0",
        json!({"type":"object"}),
        McpToolExecutionClass::ProtocolOnly,
    )
    .unwrap();
    let server_id = McpServerId::new("kind-server").unwrap();
    let local = publish_mcp_tools(
        server_id.clone(),
        McpServerKind::Local,
        vec![descriptor.clone()],
        &["read"],
    )
    .unwrap();
    let equivalent_local = publish_mcp_tools(
        server_id.clone(),
        McpServerKind::Local,
        vec![descriptor.clone()],
        &["read"],
    )
    .unwrap();
    let remote = publish_mcp_tools(
        server_id.clone(),
        McpServerKind::Remote,
        vec![descriptor],
        &["read"],
    )
    .unwrap();
    let local_ref = local.snapshot().tool_refs()[0].clone();
    let remote_ref = remote.snapshot().tool_refs()[0].clone();
    assert_ne!(local.discovery_digest(), remote.discovery_digest());
    assert_eq!(
        local.discovery_digest(),
        equivalent_local.discovery_digest()
    );
    assert_eq!(
        local.resolve(&local_ref).unwrap().class(),
        ToolClass::McpLocal
    );
    assert_eq!(
        local.resolve(&local_ref).unwrap().sandbox_profile(),
        SandboxProfile::McpLocal
    );
    assert_eq!(
        remote.resolve(&remote_ref).unwrap().class(),
        ToolClass::McpRemote
    );
    assert_eq!(
        remote.resolve(&remote_ref).unwrap().sandbox_profile(),
        SandboxProfile::NetworkRestricted
    );
    let binding = |digest| {
        McpDispatchBinding::new(
            server_id.clone(),
            McpRuntimeInstanceId::new("runtime-1").unwrap(),
            McpConnectionId::new("connection-1").unwrap(),
            McpSessionId::new("session-1").unwrap(),
            1,
            digest,
        )
        .unwrap()
    };
    let local_binding = binding(*local.discovery_digest());
    let remote_binding = binding(*remote.discovery_digest());
    assert!(matches!(
        local.issue_dispatch(
            &remote_binding,
            &local_ref,
            McpInvocationId::new("wrong-kind").unwrap(),
            json!({})
        ),
        Err(McpDispatchCapabilityError::InvalidBinding)
    ));
    let local_capability = local
        .issue_dispatch(
            &local_binding,
            &local_ref,
            McpInvocationId::new("local-kind").unwrap(),
            json!({}),
        )
        .unwrap();
    let rejected = McpToolGateway::new(
        Admission {
            calls: Arc::new(Mutex::new(Vec::new())),
            reject: None,
        },
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
    assert_eq!(
        rejected.dispatch(local_capability),
        Err(McpToolGatewayError::StaleGeneration)
    );
}

#[test]
fn publication_mapping_and_capability_execution_class_are_exact() {
    let server_id = McpServerId::new("mapping-server").unwrap();
    let protocol = McpToolDescriptor::new_with_execution_class(
        "protocol",
        "1.0.0",
        json!({"type":"object"}),
        McpToolExecutionClass::ProtocolOnly,
    )
    .unwrap();
    let process = McpToolDescriptor::new_with_execution_class(
        "process",
        "1.0.0",
        json!({"type":"object"}),
        McpToolExecutionClass::ProcessBacked,
    )
    .unwrap();
    let local = publish_mcp_tools(
        server_id.clone(),
        McpServerKind::Local,
        vec![protocol.clone(), process.clone()],
        &["protocol", "process"],
    )
    .unwrap();
    let remote = publish_mcp_tools(
        server_id.clone(),
        McpServerKind::Remote,
        vec![protocol, process],
        &["protocol", "process"],
    )
    .unwrap();
    let reference = |publication: &PublishedMcpTools, name| {
        publication
            .snapshot()
            .tool_refs()
            .iter()
            .find(|tool_ref| tool_ref.tool_id().as_str().ends_with(name))
            .unwrap()
            .clone()
    };
    let local_protocol = reference(&local, "protocol");
    let remote_protocol = reference(&remote, "protocol");
    let remote_process = reference(&remote, "process");
    for (publication, tool_ref, class, sandbox) in [
        (
            &local,
            &local_protocol,
            ToolClass::McpLocal,
            SandboxProfile::McpLocal,
        ),
        (
            &remote,
            &remote_protocol,
            ToolClass::McpRemote,
            SandboxProfile::NetworkRestricted,
        ),
        (
            &remote,
            &remote_process,
            ToolClass::BuiltInProcess,
            SandboxProfile::ProcessRestricted,
        ),
    ] {
        let definition = publication.resolve(tool_ref).unwrap();
        assert_eq!(definition.class(), class);
        assert_eq!(definition.sandbox_profile(), sandbox);
    }
    let binding = McpDispatchBinding::new(
        server_id,
        McpRuntimeInstanceId::new("runtime-1").unwrap(),
        McpConnectionId::new("connection-1").unwrap(),
        McpSessionId::new("session-1").unwrap(),
        1,
        *local.discovery_digest(),
    )
    .unwrap();
    let protocol_capability = local
        .issue_dispatch(
            &binding,
            &local_protocol,
            McpInvocationId::new("protocol-call").unwrap(),
            json!({}),
        )
        .unwrap();
    assert_eq!(
        protocol_capability.execution_class(),
        McpToolExecutionClass::ProtocolOnly
    );
    assert_ne!(
        protocol_capability.execution_class(),
        McpToolExecutionClass::ProcessBacked
    );
}

#[test]
fn protocol_request_digest_is_unchanged_by_typed_issuance_delta() {
    let published = published();
    let binding = binding(1, *published.discovery_digest());
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let invocation = McpInvocationId::new("protocol-digest").unwrap();
    let first = published
        .issue_dispatch(&binding, &tool_ref, invocation.clone(), json!({}))
        .unwrap();
    let capability = published
        .issue_dispatch(&binding, &tool_ref, invocation, json!({}))
        .unwrap();
    assert_eq!(first.execution_class(), McpToolExecutionClass::ProtocolOnly);
    assert_eq!(
        capability.execution_class(),
        McpToolExecutionClass::ProtocolOnly
    );
    let messages = Arc::new(Mutex::new(Vec::new()));
    let reservations = reservations();
    let gateway = McpToolGateway::new(
        Admission {
            calls: Arc::new(Mutex::new(Vec::new())),
            reject: None,
        },
        Client {
            sends: Arc::new(Mutex::new(0)),
            messages: Arc::clone(&messages),
            fail_after_send: false,
            generation_cutover: None,
            reservations: Arc::clone(&reservations),
        },
        Arc::new(McpGenerationAuthority::new(&binding)),
        ToolOutputBounds::new(1024, 16, 16).unwrap(),
    );
    let handle = gateway.dispatch(capability).unwrap();
    let entry = reservations
        .lock()
        .unwrap()
        .get("protocol-digest")
        .unwrap()
        .digest;
    assert_eq!(
        entry,
        [0x1a, 0xd4, 0xf1, 0xd3, 0xc8, 0xe4, 0xa5, 0x0a, 0xfa, 0xf4, 0x04, 0x44, 0xca, 0x11, 0x46, 0x5c, 0xb9, 0x34, 0x92, 0xde, 0xdd, 0x07, 0x74, 0x65, 0x6b, 0xd5, 0x4d, 0xdd, 0x8b, 0x92, 0x26, 0x03]
    );
    let request = ToolProtocolCloseRequest::new("protocol-digest".into(), entry, handle);
    let mut closer = Client {
        sends: Arc::new(Mutex::new(0)),
        messages: Arc::new(Mutex::new(Vec::new())),
        fail_after_send: false,
        generation_cutover: None,
        reservations,
    };
    assert_eq!(closer.confirm_protocol_completion(&request), Ok(()));
    let mut parameter_keys = messages.lock().unwrap()[0]
        .params()
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    parameter_keys.sort();
    assert_eq!(parameter_keys, ["arguments", "name", "runtime", "session"]);
}
