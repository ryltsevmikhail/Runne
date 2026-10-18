use crate::permission_modes::closed_coverage_test_support as support;

use crate::permission_modes::{
    ApprovalReason, ContainmentStrategy, DenyReason, FilesystemPermission, ManagedDisposition,
    NetworkScope, PermissionAction, PermissionMode, PermissionPolicyCompiler, PolicyDecision,
};
use crate::project_trust::{ManagedEffectClass, ManagedEffectDecision};
use std::collections::BTreeSet;

fn partial_scope(
    rules: [ManagedEffectDecision; 6],
) -> crate::permission_modes::CompositeEffectScope {
    let mut scope = support::broad_scope(NetworkScope::None, rules);
    scope.containment = ContainmentStrategy::SameUserCompositeV2;
    scope.filesystem.permissions = BTreeSet::from([
        FilesystemPermission::Read,
        FilesystemPermission::Create,
        FilesystemPermission::Write,
    ]);
    scope
}

fn request(
    action: PermissionAction,
    target_absent: bool,
) -> crate::permission_modes::PolicyEvaluationInput {
    request_with_rules(
        support::decisions(ManagedEffectDecision::Allow),
        action,
        target_absent,
    )
}

fn request_with_rules(
    rules: [ManagedEffectDecision; 6],
    action: PermissionAction,
    target_absent: bool,
) -> crate::permission_modes::PolicyEvaluationInput {
    let mut input = support::input_for_scope(partial_scope(rules), PermissionMode::FullAccess);
    input.invocation.action = action;
    input.invocation.candidate_binding.action = action;
    input.invocation.resource.target = if target_absent {
        crate::permission_modes::TargetState::Absent
    } else {
        crate::permission_modes::TargetState::Existing
    };
    input
}

#[test]
fn delete_deny_keeps_read_create_write_full_access_auto_admitted() {
    let mut rules = support::decisions(ManagedEffectDecision::Allow);
    rules[ManagedEffectClass::FsDelete.tag() as usize - 1] = ManagedEffectDecision::Deny;
    let scope = partial_scope(rules);
    let input = support::input_for_scope(scope, PermissionMode::FullAccess);
    assert!(matches!(
        PermissionPolicyCompiler::compile(&input),
        PolicyDecision::Allow {
            effective_mode: PermissionMode::FullAccess,
            ..
        }
    ));

    for (action, absent) in [
        (PermissionAction::FsRead, false),
        (PermissionAction::FsCreate, true),
        (PermissionAction::FsWrite, false),
    ] {
        assert!(matches!(
            PermissionPolicyCompiler::compile(&request(action, absent)),
            PolicyDecision::Allow { .. }
        ));
    }
    assert_eq!(
        PermissionPolicyCompiler::compile(&request(PermissionAction::FsDelete, false)),
        PolicyDecision::Deny(DenyReason::OutsideAdmittedScope)
    );
}

#[test]
fn ask_for_provided_right_requires_a_fresh_exact_approval() {
    let mut rules = support::decisions(ManagedEffectDecision::Allow);
    rules[ManagedEffectClass::FsRead.tag() as usize - 1] = ManagedEffectDecision::Ask;
    let mut input = support::input_for_scope(partial_scope(rules), PermissionMode::FullAccess);
    input.managed.disposition = ManagedDisposition::Ask;
    assert!(matches!(
        PermissionPolicyCompiler::compile(&input),
        PolicyDecision::RequireApproval {
            reason: ApprovalReason::ManagedAsk,
            ..
        }
    ));

    let mut stale = input.invocation.candidate_binding.clone();
    stale.expires_at_unix_ms = input.now_unix_ms;
    input.invocation.approved_binding = Some(stale);
    assert!(matches!(
        PermissionPolicyCompiler::compile(&input),
        PolicyDecision::RequireApproval {
            reason: ApprovalReason::ManagedAsk,
            ..
        }
    ));

    input.invocation.approved_binding = Some(input.invocation.candidate_binding.clone());
    assert!(matches!(
        PermissionPolicyCompiler::compile(&input),
        PolicyDecision::Allow { .. }
    ));
}

#[test]
fn ask_always_does_not_auto_admit_unknown_target_or_object() {
    for (target, object) in [
        (
            crate::permission_modes::TargetState::Unknown,
            crate::permission_modes::ObjectKind::RegularFile,
        ),
        (
            crate::permission_modes::TargetState::Existing,
            crate::permission_modes::ObjectKind::Unknown,
        ),
    ] {
        let mut input = request(PermissionAction::FsRead, false);
        input.selection.selected_mode = PermissionMode::AskAlways;
        input.effective = crate::permission_modes::admit_effective_mode(
            PermissionMode::AskAlways,
            crate::permission_modes::PresetVersion::V1,
            &input.effective_scope,
            &support::MockAdmission,
        )
        .unwrap();
        input.invocation.resource.target = target;
        input.invocation.resource.object = object;
        assert!(matches!(
            PermissionPolicyCompiler::compile(&input),
            PolicyDecision::RequireApproval {
                reason: ApprovalReason::AskAlways,
                ..
            }
        ));
    }
}

#[test]
fn partial_profile_keeps_safe_reads_and_risk_based_create_available_across_modes() {
    let mut rules = support::decisions(ManagedEffectDecision::Allow);
    rules[ManagedEffectClass::FsDelete.tag() as usize - 1] = ManagedEffectDecision::Deny;
    for mode in [PermissionMode::AskAlways, PermissionMode::RiskBased] {
        let mut read = request_with_rules(rules, PermissionAction::FsRead, false);
        read.selection.selected_mode = mode;
        read.effective = crate::permission_modes::admit_effective_mode(
            mode,
            crate::permission_modes::PresetVersion::V1,
            &read.effective_scope,
            &support::MockAdmission,
        )
        .unwrap();
        assert!(matches!(
            PermissionPolicyCompiler::compile(&read),
            PolicyDecision::Allow { .. }
        ));
        if mode == PermissionMode::RiskBased {
            let mut create = request_with_rules(rules, PermissionAction::FsCreate, true);
            create.selection.selected_mode = mode;
            create.effective = crate::permission_modes::admit_effective_mode(
                mode,
                crate::permission_modes::PresetVersion::V1,
                &create.effective_scope,
                &support::MockAdmission,
            )
            .unwrap();
            assert!(matches!(
                PermissionPolicyCompiler::compile(&create),
                PolicyDecision::Allow { .. }
            ));
        }
    }
}
