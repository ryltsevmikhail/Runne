#[test]
fn missing_selection_is_ask_always_revision_zero() {
    let missing = ModeSelection::missing(permission_scope());
    assert_eq!(missing.selected_mode, PermissionMode::AskAlways);
    assert_eq!(missing.authorization_revision, 0);
    assert_eq!(missing.preset_version, PresetVersion::V1);
    assert_eq!(missing.expires_at_unix_ms, None);
}

#[test]
fn risk_based_auto_admits_only_safe_read_or_exact_new_regular_file() {
    let read = input(
        PermissionMode::RiskBased,
        PermissionAction::FsRead,
        safe_target(),
        bounded_scope(),
    );
    assert!(matches!(
        PermissionPolicyCompiler::compile(&read),
        PolicyDecision::Allow { .. }
    ));

    let create = input(
        PermissionMode::RiskBased,
        PermissionAction::FsCreate,
        safe_create_target(),
        bounded_scope(),
    );
    assert!(matches!(
        PermissionPolicyCompiler::compile(&create),
        PolicyDecision::Allow { .. }
    ));

    for facts in [
        ResourceFacts {
            sensitivity: Sensitivity::Sensitive,
            ..safe_target()
        },
        ResourceFacts {
            size: SizeBound::Unknown,
            ..safe_target()
        },
        ResourceFacts {
            target: TargetState::Existing,
            ..safe_create_target()
        },
        ResourceFacts {
            executable: true,
            ..safe_create_target()
        },
        ResourceFacts::unknown(),
    ] {
        let request = input(
            PermissionMode::RiskBased,
            PermissionAction::FsCreate,
            facts,
            bounded_scope(),
        );
        assert!(matches!(
            PermissionPolicyCompiler::compile(&request),
            PolicyDecision::RequireApproval { .. } | PolicyDecision::Deny(_)
        ));
    }
}

#[test]
fn ask_always_prompts_for_mutations_and_network_but_allows_safe_workspace_read() {
    let read = input(
        PermissionMode::AskAlways,
        PermissionAction::FsRead,
        safe_target(),
        bounded_scope(),
    );
    assert!(matches!(
        PermissionPolicyCompiler::compile(&read),
        PolicyDecision::Allow { .. }
    ));
    let write = input(
        PermissionMode::AskAlways,
        PermissionAction::FsWrite,
        safe_target(),
        bounded_scope(),
    );
    assert!(matches!(
        PermissionPolicyCompiler::compile(&write),
        PolicyDecision::RequireApproval {
            reason: ApprovalReason::AskAlways,
            ..
        }
    ));
    let network = input(
        PermissionMode::AskAlways,
        PermissionAction::NetworkConnect,
        safe_target(),
        bounded_scope(),
    );
    assert!(matches!(
        PermissionPolicyCompiler::compile(&network),
        PolicyDecision::RequireApproval { .. }
    ));
}

#[test]
fn managed_deny_dominates_and_managed_ask_requires_exact_invocation_approval_in_all_modes() {
    for mode in [
        PermissionMode::AskAlways,
        PermissionMode::RiskBased,
        PermissionMode::FullAccess,
    ] {
        let mut denied = full_access_input(mode, PermissionAction::FsRead, outside_safe_target());
        denied.managed.disposition = ManagedDisposition::Deny;
        assert_eq!(
            PermissionPolicyCompiler::compile(&denied),
            PolicyDecision::Deny(DenyReason::ManagedPolicy)
        );

        let mut asked = full_access_input(mode, PermissionAction::FsRead, outside_safe_target());
        asked.managed.disposition = ManagedDisposition::Ask;
        assert!(matches!(
            PermissionPolicyCompiler::compile(&asked),
            PolicyDecision::RequireApproval {
                reason: ApprovalReason::ManagedAsk,
                unit: ApprovalUnit::Invocation,
                ..
            }
        ));
        asked.invocation.approved_binding = Some(asked.invocation.candidate_binding.clone());
        assert!(matches!(
            PermissionPolicyCompiler::compile(&asked),
            PolicyDecision::Allow { .. }
        ));
    }
}

#[test]
fn full_access_allows_admitted_outside_target_but_managed_allow_is_target_specific() {
    let allowed = full_access_input(
        PermissionMode::FullAccess,
        PermissionAction::FsRead,
        outside_safe_target(),
    );
    assert!(matches!(
        PermissionPolicyCompiler::compile(&allowed),
        PolicyDecision::Allow { .. }
    ));

    let mut denied_target = allowed.clone();
    denied_target.managed.disposition = ManagedDisposition::Deny;
    denied_target
        .invocation
        .candidate_binding
        .target_identity_digest = digest(42);
    assert_eq!(
        PermissionPolicyCompiler::compile(&denied_target),
        PolicyDecision::Deny(DenyReason::ManagedPolicy)
    );
}

#[test]
fn full_access_managed_restricted_snapshot_still_allows_one_typed_effect() {
    let input = full_access_input(
        PermissionMode::FullAccess,
        PermissionAction::FsRead,
        outside_safe_target(),
    );
    assert!(matches!(
        input.invocation.composite_scope.managed_policy,
        ManagedPolicyCoverage::Restricted { .. }
    ));
    assert!(matches!(
        PermissionPolicyCompiler::compile(&input),
        PolicyDecision::Allow { .. }
    ));
}
