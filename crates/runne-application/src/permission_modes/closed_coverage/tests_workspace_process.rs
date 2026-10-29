use super::*;
use crate::permission_modes::*;
#[test]
fn closed_workspace_process_retains_process_rule_and_exact_human_approval() {
    for process in [
        ManagedEffectDecision::Allow,
        ManagedEffectDecision::Ask,
        ManagedEffectDecision::Deny,
    ] {
        let mut rules = decisions(ManagedEffectDecision::Allow);
        rules[ManagedEffectClass::ProcessStart.tag() as usize - 1] = process;
        rules[ManagedEffectClass::NetworkUse.tag() as usize - 1] = ManagedEffectDecision::Deny;
        let mut scope = support::bounded_scope(
            [
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ],
            rules,
        );
        scope.children = ChildDelegationScope::Unbounded;
        scope.budget = EffectBudget {
            max_operations: Some(1),
            max_bytes: None,
        };
        assert_eq!(
            scope.managed_policy.supports_closed_scope(&scope),
            process != ManagedEffectDecision::Deny
        );
        if process == ManagedEffectDecision::Deny {
            continue;
        }
        assert_eq!(
            scope.managed_policy.scope_minimum_disposition(&scope),
            Some(process)
        );
        let mut input = support::input_for_scope(scope, PermissionMode::AskAlways);
        input.invocation.action = PermissionAction::ProcessStart;
        input.invocation.candidate_binding.action = PermissionAction::ProcessStart;
        input.invocation.candidate_binding.executable_digest =
            Some(IntegrityDigest::from_bytes([9; 32]));
        input.invocation.resource.size = SizeBound::Unbounded;
        input.invocation.resource.object = ObjectKind::Other;
        input.managed.disposition = if process == ManagedEffectDecision::Ask {
            ManagedDisposition::Ask
        } else {
            ManagedDisposition::Allow
        };
        assert!(matches!(
            PermissionPolicyCompiler::compile(&input),
            PolicyDecision::RequireApproval { .. }
        ));
        input.invocation.approved_binding = Some(input.invocation.candidate_binding.clone());
        assert!(matches!(
            PermissionPolicyCompiler::compile(&input),
            PolicyDecision::Allow { .. }
        ));
    }
}
