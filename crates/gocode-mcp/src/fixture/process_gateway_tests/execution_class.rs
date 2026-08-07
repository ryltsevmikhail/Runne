#[test]
fn typed_process_issuance_derives_its_binding_from_intent() {
    let published = publish_mcp_tools(
        McpServerId::new("fixture-server").unwrap(),
        McpServerKind::Local,
        vec![McpToolDescriptor::new_with_execution_class(
            "process",
            "1.0.0",
            json!({"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}),
            McpToolExecutionClass::ProcessBacked,
        )
        .unwrap()],
        &["process"],
    )
    .unwrap();
    let binding = binding(1, *published.discovery_digest());
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let (_, intent) = process_context();
    assert!(
        published
            .issue_process_dispatch(
                &binding,
                &tool_ref,
                McpInvocationId::new("process-call").unwrap(),
                json!({"command":"run"}),
                &intent,
            )
            .is_ok()
    );
}

#[test]
fn ordinary_process_issuance_is_fail_closed_before_typed_issuance() {
    let published = publish_mcp_tools(
        McpServerId::new("fixture-server").unwrap(),
        McpServerKind::Local,
        vec![
            McpToolDescriptor::new_with_execution_class(
                "process",
                "1.0.0",
                json!({"type":"object"}),
                McpToolExecutionClass::ProcessBacked,
            )
            .unwrap(),
        ],
        &["process"],
    )
    .unwrap();
    let binding = binding(1, *published.discovery_digest());
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let (_, intent) = process_context();
    let invocation = McpInvocationId::new("process-call").unwrap();

    assert!(matches!(
        published.issue_dispatch(&binding, &tool_ref, invocation.clone(), json!({})),
        Err(McpDispatchCapabilityError::ProcessIntentRequired)
    ));
    assert!(
        published
            .issue_process_dispatch(&binding, &tool_ref, invocation, json!({}), &intent,)
            .is_ok()
    );
}

#[test]
fn ordinary_process_issuance_reports_missing_intent_before_payload_validation() {
    let published = publish_mcp_tools(
        McpServerId::new("fixture-server").unwrap(),
        McpServerKind::Local,
        vec![McpToolDescriptor::new_with_execution_class(
            "process",
            "1.0.0",
            json!({"type":"object","properties":{"command":{"type":"string"}},"required":["command"],"additionalProperties":false}),
            McpToolExecutionClass::ProcessBacked,
        )
        .unwrap()],
        &["process"],
    )
    .unwrap();
    let binding = binding(1, *published.discovery_digest());
    let tool_ref = published.snapshot().tool_refs()[0].clone();

    for (index, input) in [
        json!({"api_key":"untrusted"}),
        json!({"command":"x".repeat(20_000)}),
        json!({"unexpected":true}),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(matches!(
            published.issue_dispatch(
                &binding,
                &tool_ref,
                McpInvocationId::new(format!("process-untyped-{index}")).unwrap(),
                input,
            ),
            Err(McpDispatchCapabilityError::ProcessIntentRequired)
        ));
    }
}

#[test]
fn process_dispatch_validates_the_original_schema_without_control_fields() {
    let published = publish_mcp_tools(
        McpServerId::new("fixture-server").unwrap(),
        McpServerKind::Local,
        vec![McpToolDescriptor::new_with_execution_class(
            "process",
            "1.0.0",
            json!({"type":"object","properties":{"command":{"type":"string"}},"required":["command"],"additionalProperties":false}),
            McpToolExecutionClass::ProcessBacked,
        )
        .unwrap()],
        &["process"],
    )
    .unwrap();
    let binding = binding(1, *published.discovery_digest());
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let (_, intent) = process_context();

    assert!(
        published
            .issue_process_dispatch(
                &binding,
                &tool_ref,
                McpInvocationId::new("process-schema").unwrap(),
                json!({"command":"run"}),
                &intent,
            )
            .is_ok()
    );
    assert!(matches!(
        published.issue_process_dispatch(
            &binding,
            &tool_ref,
            McpInvocationId::new("process-schema-extra").unwrap(),
            json!({"command":"run","extra":true}),
            &intent,
        ),
        Err(McpDispatchCapabilityError::InvalidInput(_))
    ));
}

#[test]
fn typed_process_issuance_rejects_protocol_only_class() {
    let published = publish_mcp_tools(
        McpServerId::new("fixture-server").unwrap(),
        McpServerKind::Local,
        vec![
            McpToolDescriptor::new_with_execution_class(
                "protocol",
                "1.0.0",
                json!({"type":"object"}),
                McpToolExecutionClass::ProtocolOnly,
            )
            .unwrap(),
        ],
        &["protocol"],
    )
    .unwrap();
    let binding = binding(1, *published.discovery_digest());
    let (_, intent) = process_context();

    assert!(matches!(
        published.issue_process_dispatch(
            &binding,
            &published.snapshot().tool_refs()[0],
            McpInvocationId::new("protocol-process").unwrap(),
            json!({}),
            &intent,
        ),
        Err(McpDispatchCapabilityError::ExecutionClassMismatch)
    ));
}

#[test]
fn typed_process_issuance_reports_protocol_mismatch_before_payload_validation() {
    let published = publish_mcp_tools(
        McpServerId::new("fixture-server").unwrap(),
        McpServerKind::Local,
        vec![McpToolDescriptor::new_with_execution_class(
            "protocol",
            "1.0.0",
            json!({"type":"object","properties":{"command":{"type":"string"}},"required":["command"],"additionalProperties":false}),
            McpToolExecutionClass::ProtocolOnly,
        )
        .unwrap()],
        &["protocol"],
    )
    .unwrap();
    let binding = binding(1, *published.discovery_digest());
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let (_, intent) = process_context();

    for (index, input) in [
        json!({"api_key":"untrusted"}),
        json!({"command":"x".repeat(20_000)}),
        json!({"unexpected":true}),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(matches!(
            published.issue_process_dispatch(
                &binding,
                &tool_ref,
                McpInvocationId::new(format!("protocol-typed-{index}")).unwrap(),
                input,
                &intent,
            ),
            Err(McpDispatchCapabilityError::ExecutionClassMismatch)
        ));
    }
}

#[test]
fn process_intent_binding_is_crate_private_and_request_digest_is_independent() {
    let descriptor = include_str!("../../discovery/descriptor.rs");
    let issuance = include_str!("../../discovery/issuance.rs");

    assert!(descriptor.contains("process_intent_digest: Option<ProcessIntentDigestV1>"));
    assert!(!descriptor.contains("process_intent_digest("));
    assert!(!descriptor.contains("ProcessIntentV1"));
    assert!(
        issuance.contains(
            "let request_digest = call_digest(binding, tool_ref, &invocation_id, &input);"
        )
    );
    assert!(
        !include_str!("../../discovery/gateway.rs")
            .contains(concat!("process_call_", "digest"))
    );
}
