#[test]
fn concurrent_process_dispatch_cannot_overwrite_an_in_flight_invocation() {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let binding = binding(1, *published.discovery_digest());
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let invocation = McpInvocationId::new("concurrent-call").unwrap();
    let (boundary, intent) = process_context_for(&binding, &invocation);
    let first_process_capability = boundary.issue_capability(&intent, 20).unwrap();
    let first_approval = boundary.approve(&intent, 20, true).unwrap();
    let second_process_capability = boundary.issue_capability(&intent, 20).unwrap();
    let second_approval = boundary.approve(&intent, 20, true).unwrap();
    let first = published
        .issue_process_dispatch(
            &binding,
            &tool_ref,
            invocation.clone(),
            json!({}),
            &intent,
        )
        .unwrap();
    let second = published
        .issue_process_dispatch(&binding, &tool_ref, invocation, json!({}), &intent)
        .unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let gateway = Arc::new(process_gateway(
        boundary,
        Arc::new(BlockingQualifiedProbe {
            calls: std::sync::atomic::AtomicUsize::new(0),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }),
        Arc::new(McpGenerationAuthority::new(&binding)),
    ));
    let first_gateway = Arc::clone(&gateway);
    let first_intent = intent.clone();
    let first_thread = std::thread::spawn(move || {
        first_gateway.dispatch(process_call(
            first,
            first_intent,
            first_process_capability,
            first_approval,
        ))
    });
    entered_rx.recv().unwrap();

    assert!(matches!(
        gateway.dispatch(process_call(
            second,
            intent,
            second_process_capability,
            second_approval,
        )),
        Err(McpProcessGatewayError::Unavailable | McpProcessGatewayError::InvalidBinding)
    ));
    release_tx.send(()).unwrap();
    assert_eq!(
        first_thread.join().unwrap(),
        Err(McpProcessGatewayError::Uncertain)
    );
    assert_eq!(gateway.effect_admission_count(), 1);
}

#[test]
fn authority_advance_during_blocked_containment_cannot_win_effect_admission() {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let binding = binding(1, *published.discovery_digest());
    let invocation = McpInvocationId::new("advance-after-preflight").unwrap();
    let (authority, intent) = process_context_for(&binding, &invocation);
    let process_capability = authority.issue_capability(&intent, 20).unwrap();
    let approval = authority.approve(&intent, 20, true).unwrap();
    let capability = published
        .issue_process_dispatch(
            &binding,
            &published.snapshot().tool_refs()[0],
            invocation,
            json!({}),
            &intent,
        )
        .unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let gateway = Arc::new(process_gateway(
        authority.clone(),
        Arc::new(BlockingQualifiedProbe {
            calls: std::sync::atomic::AtomicUsize::new(0),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }),
        Arc::new(McpGenerationAuthority::new(&binding)),
    ));
    let task_gateway = Arc::clone(&gateway);
    let task = std::thread::spawn(move || {
        task_gateway.dispatch(process_call(capability, intent, process_capability, approval))
    });
    entered_rx.recv().unwrap();
    authority.prepare_advance().unwrap().commit().unwrap();
    release_tx.send(()).unwrap();

    assert_eq!(
        task.join().unwrap(),
        Err(McpProcessGatewayError::Authorization(
            ProcessContractError::CapabilityInvalid
        ))
    );
    assert_eq!(gateway.effect_admission_count(), 0);
}

#[test]
fn qualified_probe_records_sticky_uncertain_without_redispatch() {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let binding = binding(1, *published.discovery_digest());
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let invocation = McpInvocationId::new("uncertain-call").unwrap();
    let (boundary, intent) = process_context_for(&binding, &invocation);
    let first_capability = boundary.issue_capability(&intent, 20).unwrap();
    let first_approval = boundary.approve(&intent, 20, true).unwrap();
    let retry_capability = boundary.issue_capability(&intent, 20).unwrap();
    let retry_approval = boundary.approve(&intent, 20, true).unwrap();
    let first = published
        .issue_process_dispatch(
            &binding,
            &tool_ref,
            invocation.clone(),
            json!({}),
            &intent,
        )
        .unwrap();
    let retry = published
        .issue_process_dispatch(&binding, &tool_ref, invocation, json!({}), &intent)
        .unwrap();
    let gateway = process_gateway(
        boundary,
        Arc::new(QualifiedProbe),
        Arc::new(McpGenerationAuthority::new(&binding)),
    );

    assert_eq!(
        gateway.dispatch(process_call(
            first,
            intent.clone(),
            first_capability,
            first_approval
        )),
        Err(McpProcessGatewayError::Uncertain)
    );
    assert_eq!(
        gateway.host_outcome("uncertain-call"),
        Some(ProcessLifecycleStateV1::Uncertain)
    );
    assert_eq!(gateway.effect_admission_count(), 1);
    assert_eq!(
        gateway.dispatch(process_call(
            retry,
            intent,
            retry_capability,
            retry_approval
        )),
        Err(McpProcessGatewayError::Uncertain)
    );
    assert_eq!(gateway.effect_admission_count(), 1);
}

#[test]
fn denied_host_outcome_after_effect_admission_is_sticky_uncertain() {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let binding = binding(1, *published.discovery_digest());
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let invocation = McpInvocationId::new("denied-host").unwrap();
    let (boundary, intent) = process_context_for(&binding, &invocation);
    let first_capability = boundary.issue_capability(&intent, 20).unwrap();
    let first_approval = boundary.approve(&intent, 20, true).unwrap();
    let retry_capability = boundary.issue_capability(&intent, 20).unwrap();
    let retry_approval = boundary.approve(&intent, 20, true).unwrap();
    let first = published
        .issue_process_dispatch(
            &binding,
            &tool_ref,
            invocation.clone(),
            json!({}),
            &intent,
        )
        .unwrap();
    let retry = published
        .issue_process_dispatch(&binding, &tool_ref, invocation, json!({}), &intent)
        .unwrap();
    let gateway = process_gateway_with_clock(
        boundary,
        Arc::new(QualifiedProbe),
        Arc::new(McpGenerationAuthority::new(&binding)),
        u64::MAX,
    );

    assert_eq!(
        gateway.dispatch(process_call(
            first,
            intent.clone(),
            first_capability,
            first_approval
        )),
        Err(McpProcessGatewayError::Uncertain)
    );
    assert_eq!(gateway.effect_admission_count(), 1);
    assert_eq!(
        gateway.dispatch(process_call(
            retry,
            intent,
            retry_capability,
            retry_approval
        )),
        Err(McpProcessGatewayError::Uncertain)
    );
    assert_eq!(gateway.effect_admission_count(), 1);
}

#[test]
fn stale_generation_precedes_exact_terminal_replay_without_mutating_the_terminal() {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let active_binding = binding(1, *published.discovery_digest());
    let next_binding = binding(2, *published.discovery_digest());
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let invocation = McpInvocationId::new("stale-terminal").unwrap();
    let (boundary, intent) = process_context_for(&active_binding, &invocation);
    let first_capability = boundary.issue_capability(&intent, 20).unwrap();
    let first_approval = boundary.approve(&intent, 20, true).unwrap();
    let replay_capability = boundary.issue_capability(&intent, 20).unwrap();
    let replay_approval = boundary.approve(&intent, 20, true).unwrap();
    let first = published
        .issue_process_dispatch(
            &active_binding,
            &tool_ref,
            invocation.clone(),
            json!({}),
            &intent,
        )
        .unwrap();
    let replay = published
        .issue_process_dispatch(&active_binding, &tool_ref, invocation, json!({}), &intent)
        .unwrap();
    let generation = Arc::new(McpGenerationAuthority::new(&active_binding));
    let gateway = process_gateway(
        boundary,
        Arc::new(QualifiedProbe),
        Arc::clone(&generation),
    );

    assert_eq!(
        gateway.dispatch(process_call(first, intent.clone(), first_capability, first_approval)),
        Err(McpProcessGatewayError::Uncertain)
    );
    assert_eq!(gateway.effect_admission_count(), 1);
    assert_eq!(gateway.host_outcome("stale-terminal"), Some(ProcessLifecycleStateV1::Uncertain));
    assert_eq!(generation.try_advance(&next_binding), Ok(()));

    assert_eq!(
        gateway.dispatch(process_call(replay, intent, replay_capability, replay_approval)),
        Err(McpProcessGatewayError::StaleGeneration)
    );
    assert_eq!(gateway.effect_admission_count(), 1);
    assert_eq!(gateway.host_outcome("stale-terminal"), Some(ProcessLifecycleStateV1::Uncertain));
}
