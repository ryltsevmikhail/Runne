#[test]
fn workspace_process_requires_exact_approval_and_containment() {
    let mut scope = bounded_scope();
    scope.network = NetworkScope::None;
    scope.children = ChildDelegationScope::Unbounded;
    scope.budget = EffectBudget {
        max_operations: Some(1),
        max_bytes: None,
    };
    let mut facts = safe_target();
    facts.object = ObjectKind::Other;
    facts.size = SizeBound::Unbounded;
    let mut request = input(
        PermissionMode::AskAlways,
        PermissionAction::ProcessStart,
        facts,
        scope,
    );
    assert!(matches!(
        PermissionPolicyCompiler::compile(&request),
        PolicyDecision::RequireApproval { .. }
    ));
    request.invocation.approved_binding = Some(request.invocation.candidate_binding.clone());
    assert!(matches!(
        PermissionPolicyCompiler::compile(&request),
        PolicyDecision::Allow { .. }
    ));
    let mut no_image = request.clone();
    no_image.invocation.candidate_binding.executable_digest = None;
    assert!(matches!(
        PermissionPolicyCompiler::compile(&no_image),
        PolicyDecision::Deny(_)
    ));
    let mut no_native = request.clone();
    no_native.invocation.native_admission = None;
    assert!(matches!(
        PermissionPolicyCompiler::compile(&no_native),
        PolicyDecision::Deny(_)
    ));
    request.invocation.resource.resolved_path =
        Some(FilesystemRoot::new(digest(88), vec![]).unwrap());
    assert!(matches!(
        PermissionPolicyCompiler::compile(&request),
        PolicyDecision::Deny(_)
    ));
}

#[test]
fn workspace_process_rejects_network_or_unbounded_operation_grants() {
    for variant in 0..4 {
        let mut scope = bounded_scope();
        scope.network = NetworkScope::None;
        scope.children = ChildDelegationScope::Unbounded;
        scope.budget = EffectBudget {
            max_operations: Some(1),
            max_bytes: None,
        };
        match variant {
            0 => {
                scope.network = NetworkScope::Brokered {
                    policy_digest: digest(23),
                }
            }
            1 => scope.budget.max_operations = None,
            2 => scope.children = ChildDelegationScope::None,
            _ => {
                scope
                    .filesystem
                    .permissions
                    .remove(&FilesystemPermission::Delete);
            }
        }
        let mut request = input(
            PermissionMode::RiskBased,
            PermissionAction::ProcessStart,
            safe_target(),
            scope,
        );
        request.invocation.approved_binding = Some(request.invocation.candidate_binding.clone());
        assert!(matches!(
            PermissionPolicyCompiler::compile(&request),
            PolicyDecision::Deny(_)
        ));
    }
}
