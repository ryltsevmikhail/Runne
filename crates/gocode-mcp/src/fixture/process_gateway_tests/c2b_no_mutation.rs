fn process_calls_for_c2b_rejection(
    invocation_id: &str,
) -> (McpProcessToolGateway, McpProcessCall, McpProcessCall) {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let binding = binding(1, *published.discovery_digest());
    let invocation = McpInvocationId::new(invocation_id).unwrap();
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let (boundary, intent) = process_context_for(&binding, &invocation);
    let rejected_capability = boundary.issue_capability(&intent, 20).unwrap();
    let rejected_approval = boundary.approve(&intent, 20, true).unwrap();
    let valid_capability = boundary.issue_capability(&intent, 20).unwrap();
    let valid_approval = boundary.approve(&intent, 20, true).unwrap();
    let rejected = published
        .issue_process_dispatch(&binding, &tool_ref, invocation.clone(), json!({}), &intent)
        .unwrap();
    let valid = published
        .issue_process_dispatch(&binding, &tool_ref, invocation, json!({}), &intent)
        .unwrap();
    let gateway = process_gateway(
        boundary,
        Arc::new(QualifiedProbe),
        Arc::new(McpGenerationAuthority::new(&binding)),
    );

    (
        gateway,
        process_call(rejected, intent.clone(), rejected_capability, rejected_approval),
        process_call(valid, intent, valid_capability, valid_approval),
    )
}

fn assert_rejection_left_gateway_unchanged(
    gateway: &McpProcessToolGateway,
    invocation_id: &str,
    before: Option<(usize, usize, usize, usize)>,
) {
    assert_eq!(gateway.effect_admission_count(), 0);
    assert_eq!(gateway.host_outcome(invocation_id), None);
    assert_eq!(gateway.test_state_counts(), before);
}

#[test]
fn missing_process_intent_digest_is_rejected_before_gateway_mutation() {
    let (gateway, rejected, valid) = process_calls_for_c2b_rejection("missing-intent");
    let before = gateway.test_state_counts();

    assert_eq!(
        gateway.dispatch(rejected.without_process_intent_digest_for_test()),
        Err(McpProcessGatewayError::ProcessIntentRequired)
    );
    assert_rejection_left_gateway_unchanged(&gateway, "missing-intent", before);
    assert_eq!(gateway.dispatch(valid), Err(McpProcessGatewayError::Uncertain));
    assert_eq!(gateway.effect_admission_count(), 1);
}

#[test]
fn forged_invocation_is_rejected_before_gateway_mutation() {
    let (gateway, rejected, valid) = process_calls_for_c2b_rejection("valid-invocation");
    let before = gateway.test_state_counts();

    assert_eq!(
        gateway.dispatch(rejected.with_invocation_id_for_test("forged-invocation")),
        Err(McpProcessGatewayError::InvalidBinding)
    );
    assert_rejection_left_gateway_unchanged(&gateway, "valid-invocation", before);
    assert_eq!(gateway.dispatch(valid), Err(McpProcessGatewayError::Uncertain));
    assert_eq!(gateway.effect_admission_count(), 1);
}
