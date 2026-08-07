#[test]
fn process_gateway_rejects_protocol_only_before_effect_admission() {
    let (boundary, intent) = process_context();
    let process_capability = boundary.issue_capability(&intent, 20).unwrap();
    let approval = boundary.approve(&intent, 20, true).unwrap();
    let published = publication(McpToolExecutionClass::ProtocolOnly);
    let dispatch_binding = binding(1, *published.discovery_digest());
    let capability = published
        .issue_dispatch(
            &dispatch_binding,
            &published.snapshot().tool_refs()[0],
            McpInvocationId::new("protocol-call").unwrap(),
            json!({}),
        )
        .unwrap();
    let generation = Arc::new(McpGenerationAuthority::new(&dispatch_binding));
    let gateway = process_gateway(
        boundary,
        Arc::new(QualifiedProbe),
        Arc::clone(&generation),
    );

    assert_eq!(
        gateway.dispatch(process_call(
            capability,
            intent,
            process_capability,
            approval
        )),
        Err(McpProcessGatewayError::ExecutionClassMismatch)
    );
    assert_eq!(gateway.effect_admission_count(), 0);
    assert_eq!(gateway.host_outcome("protocol-call"), None);
    assert_eq!(generation.try_advance(&binding(2, *published.discovery_digest())), Ok(()));
}

#[test]
fn production_probe_rejects_valid_process_call_before_effect_admission() {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let binding = binding(1, *published.discovery_digest());
    let invocation = McpInvocationId::new("not-qualified").unwrap();
    let (boundary, intent) = process_context_for(&binding, &invocation);
    let process_capability = boundary.issue_capability(&intent, 20).unwrap();
    let approval = boundary.approve(&intent, 20, true).unwrap();
    let capability = published
        .issue_process_dispatch(
            &binding,
            &published.snapshot().tool_refs()[0],
            invocation,
            json!({}),
            &intent,
        )
        .unwrap();
    let gateway = process_gateway(
        boundary,
        Arc::new(production_sandbox_probe()),
        Arc::new(McpGenerationAuthority::new(&binding)),
    );

    assert_eq!(
        gateway.dispatch(process_call(
            capability,
            intent,
            process_capability,
            approval
        )),
        Err(McpProcessGatewayError::Sandbox(
            ProcessStubDisposition::NotQualified
        ))
    );
    assert_eq!(gateway.effect_admission_count(), 0);
    assert_eq!(gateway.host_outcome("not-qualified"), None);
}

#[test]
fn rejected_process_approval_does_not_reach_effect_admission() {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let binding = binding(1, *published.discovery_digest());
    let invocation = McpInvocationId::new("rejected-approval").unwrap();
    let (boundary, intent) = process_context_for(&binding, &invocation);
    let process_capability = boundary.issue_capability(&intent, 20).unwrap();
    let approval = boundary.approve(&intent, 20, false).unwrap();
    let capability = published
        .issue_process_dispatch(
            &binding,
            &published.snapshot().tool_refs()[0],
            invocation,
            json!({}),
            &intent,
        )
        .unwrap();
    let gateway = process_gateway(
        boundary,
        Arc::new(QualifiedProbe),
        Arc::new(McpGenerationAuthority::new(&binding)),
    );

    assert_eq!(
        gateway.dispatch(process_call(
            capability,
            intent,
            process_capability,
            approval
        )),
        Err(McpProcessGatewayError::Authorization(
            ProcessContractError::ApprovalInvalid
        ))
    );
    assert_eq!(gateway.effect_admission_count(), 0);
}

#[test]
fn rejected_process_approval_does_not_poison_a_fresh_process_call() {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let binding = binding(1, *published.discovery_digest());
    let invocation = McpInvocationId::new("retry-after-rejection").unwrap();
    let (boundary, intent) = process_context_for(&binding, &invocation);
    let rejected_capability = boundary.issue_capability(&intent, 20).unwrap();
    let rejected_approval = boundary.approve(&intent, 20, false).unwrap();
    let fresh_capability = boundary.issue_capability(&intent, 20).unwrap();
    let fresh_approval = boundary.approve(&intent, 20, true).unwrap();
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let rejected = published
        .issue_process_dispatch(&binding, &tool_ref, invocation.clone(), json!({}), &intent)
        .unwrap();
    let fresh = published
        .issue_process_dispatch(&binding, &tool_ref, invocation, json!({}), &intent)
        .unwrap();
    let gateway = process_gateway(
        boundary,
        Arc::new(production_sandbox_probe()),
        Arc::new(McpGenerationAuthority::new(&binding)),
    );

    assert_eq!(
        gateway.dispatch(process_call(
            rejected,
            intent.clone(),
            rejected_capability,
            rejected_approval
        )),
        Err(McpProcessGatewayError::Authorization(
            ProcessContractError::ApprovalInvalid
        ))
    );
    assert_eq!(
        gateway.dispatch(process_call(
            fresh,
            intent,
            fresh_capability,
            fresh_approval
        )),
        Err(McpProcessGatewayError::Sandbox(
            ProcessStubDisposition::NotQualified
        ))
    );
    assert_eq!(gateway.effect_admission_count(), 0);
}

#[test]
fn process_executor_selects_process_completion_and_source_has_no_protocol_close_path() {
    fn requires_process_completion<E: ToolExecutorPort<CompletionMode = ProcessCompletion>>() {}

    requires_process_completion::<McpProcessExecutor>();
    let source = include_str!("../process_gateway/terminal.rs");
    assert!(source.contains(".close(ToolCloseRequest"));
    let record = source.find("self.record_completed(request, &handle)?").unwrap();
    assert!(source[record..].contains("Ok(handle)"));
    assert!(source.contains("process_terminal: true"));
    assert!(source.contains("containment_released: true"));
    assert!(source.contains("cleanup_closed: true"));
    assert!(!source.contains("close_protocol"));
}
