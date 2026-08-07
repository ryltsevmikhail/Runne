#[test]
fn new_generation_dispatch_completes_after_authorization_unlock() {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let initial = binding(1, *published.discovery_digest());
    let current = binding(2, *published.discovery_digest());
    let invocation = McpInvocationId::new("pre-auth-lock").unwrap();
    let (authority, intent) = process_context_for(&current, &invocation);
    let process_capability = authority.issue_capability(&intent, 20).unwrap();
    let approval = authority.approve(&intent, 20, true).unwrap();
    let capability = published
        .issue_process_dispatch(
            &current,
            &published.snapshot().tool_refs()[0],
            invocation,
            json!({}),
            &intent,
        )
        .unwrap();
    let generation = Arc::new(McpGenerationAuthority::new(&initial));
    let mut generation_advance = generation.prepare_advance(&current).unwrap();
    generation_advance.apply_retaining_lock();
    drop(generation_advance);
    let gateway_authority = authority.clone();
    let mut authorization_advance = authority.prepare_advance().unwrap();
    authorization_advance.apply_retaining_lock();
    drop(authorization_advance);
    let gateway = Arc::new(process_gateway(
        gateway_authority,
        Arc::new(QualifiedProbe),
        generation,
    ));
    let (result_sender, result_receiver) = std::sync::mpsc::channel();
    let task_gateway = Arc::clone(&gateway);
    let task = std::thread::spawn(move || {
        result_sender.send(task_gateway.dispatch(process_call(
            capability,
            intent,
            process_capability,
            approval,
        )))
    });

    let result = result_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    task.join().unwrap().unwrap();
    assert_eq!(
        result,
        Err(McpProcessGatewayError::Authorization(
            ProcessContractError::CapabilityInvalid
        ))
    );
}
