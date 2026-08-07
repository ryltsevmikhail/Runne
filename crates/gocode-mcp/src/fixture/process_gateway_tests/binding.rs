#[test]
fn process_gateway_rejects_a_different_carried_intent_before_effect_admission() {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let binding = binding(1, *published.discovery_digest());
    let invocation = McpInvocationId::new("wrong-intent").unwrap();
    let (_, issued_intent) = process_context_with_material(
        &binding,
        &invocation,
        b"noop",
        1,
        4,
    );
    let (boundary, carried_intent) = process_context_for(&binding, &invocation);
    let process_capability = boundary.issue_capability(&carried_intent, 20).unwrap();
    let approval = boundary.approve(&carried_intent, 20, true).unwrap();
    let retry_process_capability = boundary.issue_capability(&carried_intent, 20).unwrap();
    let retry_approval = boundary.approve(&carried_intent, 20, true).unwrap();
    let capability = published
        .issue_process_dispatch(
            &binding,
            &published.snapshot().tool_refs()[0],
            invocation.clone(),
            json!({}),
            &issued_intent,
        )
        .unwrap();
    let retry = published
        .issue_process_dispatch(
            &binding,
            &published.snapshot().tool_refs()[0],
            invocation,
            json!({}),
            &carried_intent,
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
            carried_intent.clone(),
            process_capability,
            approval
        )),
        Err(McpProcessGatewayError::ProcessIntentMismatch)
    );
    assert_eq!(gateway.effect_admission_count(), 0);
    assert_eq!(gateway.host_outcome("wrong-intent"), None);
    assert_eq!(
        gateway.dispatch(process_call(
            retry,
            carried_intent,
            retry_process_capability,
            retry_approval
        )),
        Err(McpProcessGatewayError::Uncertain)
    );
    assert_eq!(gateway.effect_admission_count(), 1);
}

#[test]
fn process_gateway_rejects_a_validated_but_wrong_lifecycle_before_containment() {
    let (boundary, intent) = process_context();
    let process_capability = boundary.issue_capability(&intent, 20).unwrap();
    let approval = boundary.approve(&intent, 20, true).unwrap();
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let binding = binding(1, *published.discovery_digest());
    let capability = published
        .issue_process_dispatch(
            &binding,
            &published.snapshot().tool_refs()[0],
            McpInvocationId::new("wrong-lifecycle").unwrap(),
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
        gateway.dispatch(process_call(capability, intent, process_capability, approval)),
        Err(McpProcessGatewayError::InvalidBinding)
    );
    assert_eq!(gateway.effect_admission_count(), 0);
}

#[test]
fn process_capability_rejects_mutated_intent_material_before_effect_admission() {
    for (name, command, executable_seed, cwd_seed) in [
        ("argv", b"nope".as_slice(), 1, 4),
        ("executable", b"tool".as_slice(), 2, 4),
        ("cwd", b"tool".as_slice(), 1, 5),
    ] {
        let published = publication(McpToolExecutionClass::ProcessBacked);
        let binding = binding(1, *published.discovery_digest());
        let invocation = McpInvocationId::new(format!("mutated-{name}")).unwrap();
        let (boundary, original) = process_context_for(&binding, &invocation);
        let (_, mutated) = process_context_with_material(
            &binding,
            &invocation,
            command,
            executable_seed,
            cwd_seed,
        );
        let process_capability = boundary.issue_capability(&original, 20).unwrap();
        let approval = boundary.approve(&original, 20, true).unwrap();
        let capability = published
            .issue_process_dispatch(
                &binding,
                &published.snapshot().tool_refs()[0],
                invocation,
                json!({}),
                &mutated,
            )
            .unwrap();
        let gateway = process_gateway(
            boundary,
            Arc::new(QualifiedProbe),
            Arc::new(McpGenerationAuthority::new(&binding)),
        );

        assert_eq!(
            gateway.dispatch(process_call(capability, mutated, process_capability, approval)),
            Err(McpProcessGatewayError::Authorization(
                ProcessContractError::CapabilityInvalid
            ))
        );
        assert_eq!(gateway.effect_admission_count(), 0);
    }
}

#[test]
fn generation_claim_permit_remains_crate_private_and_not_reexported() {
    let source = include_str!("../../discovery/generation.rs");

    assert!(source.contains("pub(crate) fn claim_dispatch"));
    assert!(source.contains("pub(crate) struct McpGenerationReadPermit"));
    assert!(source.contains("pub(crate) fn matches"));
    assert!(!source.contains("pub fn claim_dispatch"));
    assert!(!include_str!("../../lib.rs").contains("McpGenerationReadPermit"));
}

#[test]
fn process_identity_derivation_is_stable_nonzero_and_binding_specific() {
    let published = publication(McpToolExecutionClass::ProcessBacked);
    let first = binding(1, *published.discovery_digest());
    let second = McpDispatchBinding::new(
        McpServerId::new("fixture-server").unwrap(),
        McpRuntimeInstanceId::new("runtime-1").unwrap(),
        McpConnectionId::new("connection-2").unwrap(),
        McpSessionId::new("session-1").unwrap(),
        2,
        *published.discovery_digest(),
    )
    .unwrap();
    let invocation = McpInvocationId::new("derived-identity").unwrap();
    let identity = |binding: &McpDispatchBinding| {
        derive_process_identity_binding(
            binding,
            &invocation,
            PrincipalId::new(process_id(7)).unwrap(),
            AuthorityId::new(process_id(8)).unwrap(),
            CapabilityGrantId::new(process_id(13)).unwrap(),
            SandboxId::new(process_id(14)).unwrap(),
        )
    };
    let stable = identity(&first);
    let repeated = identity(&first);
    let changed = identity(&second);

    assert_eq!(stable, repeated);
    assert_ne!(stable.owner(), changed.owner());
    assert_ne!(stable.generation(), changed.generation());
    for value in [
        stable.owner().as_bytes(),
        stable.attempt().as_bytes(),
        stable.session().as_bytes(),
        stable.generation().as_bytes(),
        stable.tree().as_bytes(),
    ] {
        assert_ne!(value, &[0; 16]);
    }
}

#[test]
fn c2b_guard_precedes_terminal_replay_and_all_stateful_gateway_steps() {
    let dispatch = include_str!("../process_gateway/dispatch.rs");
    let guard = dispatch.find("call.capability\n            .verify_c2b").unwrap();

    for step in [
        ".terminals",
        ".claim_dispatch",
        ".pending",
        ".gateway.dispatch",
    ] {
        assert!(dispatch[guard..].find(step).is_some(), "C2b guard must precede {step}");
    }
}
