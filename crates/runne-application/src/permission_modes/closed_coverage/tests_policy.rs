use crate::permission_modes::{
    ApprovalReason, DenyReason, FilesystemPermission, ManagedDisposition, ManagedPolicyCoverage,
    NativeAdmissionError, NetworkScope, PermissionAction, PermissionMode, PermissionPolicyCompiler,
    PolicyDecision, PresetVersion, admit_effective_mode,
};
use crate::project_trust::{ManagedEffectClass, ManagedEffectDecision};

use super::support::{
    MockAdmission, UnavailableAdmission, bounded_scope, broad_scope, decisions, digest,
    input_for_read, input_for_scope,
};

#[test]
fn broad_scope_aggregates_all_required_class_asks_before_action_labels() {
    for asked_class in [
        ManagedEffectClass::ProcessStart,
        ManagedEffectClass::FsWrite,
    ] {
        let mut rules = decisions(ManagedEffectDecision::Allow);
        rules[asked_class.tag() as usize - 1] = ManagedEffectDecision::Ask;
        let scope = broad_scope(NetworkScope::None, rules);
        assert_eq!(
            crate::permission_modes::compiler::closed_coverage::check_minimum(
                &scope,
                PermissionAction::FsRead,
                ManagedDisposition::Allow,
            ),
            Err(DenyReason::ScopeOrEvidenceMismatch)
        );
        assert_eq!(
            crate::permission_modes::compiler::closed_coverage::check_minimum(
                &scope,
                PermissionAction::FsRead,
                ManagedDisposition::Ask,
            ),
            Ok(())
        );
    }
}

#[test]
fn network_none_ignores_unused_network_ask_but_network_broad_requires_it() {
    let mut rules = decisions(ManagedEffectDecision::Allow);
    rules[ManagedEffectClass::NetworkUse.tag() as usize - 1] = ManagedEffectDecision::Ask;
    let none = broad_scope(NetworkScope::None, rules);
    assert_eq!(
        crate::permission_modes::compiler::closed_coverage::check_minimum(
            &none,
            PermissionAction::FsRead,
            ManagedDisposition::Allow,
        ),
        Ok(())
    );
    let broad = broad_scope(NetworkScope::BroadSameUser, rules);
    assert_eq!(
        crate::permission_modes::compiler::closed_coverage::check_minimum(
            &broad,
            PermissionAction::FsRead,
            ManagedDisposition::Allow,
        ),
        Err(DenyReason::ScopeOrEvidenceMismatch)
    );
}

#[test]
fn workspace_scope_process_action_is_denied_even_when_fs_read_is_granted() {
    let scope = bounded_scope(
        [FilesystemPermission::Read],
        decisions(ManagedEffectDecision::Allow),
    );
    assert_eq!(
        crate::permission_modes::compiler::closed_coverage::check_minimum(
            &scope,
            PermissionAction::ProcessStart,
            ManagedDisposition::Allow,
        ),
        Err(DenyReason::OutsideAdmittedScope)
    );
}

#[test]
fn mock_unavailable_backend_keeps_all_three_modes_not_ready() {
    let scope = broad_scope(
        NetworkScope::BroadSameUser,
        decisions(ManagedEffectDecision::Allow),
    );
    for mode in [
        PermissionMode::AskAlways,
        PermissionMode::RiskBased,
        PermissionMode::FullAccess,
    ] {
        assert_eq!(
            admit_effective_mode(mode, PresetVersion::V1, &scope, &UnavailableAdmission),
            Err(NativeAdmissionError::EnforcementUnavailable)
        );
    }
}

#[test]
fn full_access_readiness_accepts_closed_network_none_and_preserves_legacy_broad_gate() {
    let mut rules = decisions(ManagedEffectDecision::Allow);
    rules[ManagedEffectClass::NetworkUse.tag() as usize - 1] = ManagedEffectDecision::Deny;
    let closed_none = broad_scope(NetworkScope::None, rules);
    assert!(
        admit_effective_mode(
            PermissionMode::FullAccess,
            PresetVersion::V1,
            &closed_none,
            &MockAdmission,
        )
        .is_ok()
    );

    rules[ManagedEffectClass::ProcessStart.tag() as usize - 1] = ManagedEffectDecision::Deny;
    let denied_process = broad_scope(NetworkScope::None, rules);
    assert_eq!(
        admit_effective_mode(
            PermissionMode::FullAccess,
            PresetVersion::V1,
            &denied_process,
            &MockAdmission,
        ),
        Err(NativeAdmissionError::CompositePolicyUnenforceable)
    );

    let mut legacy = broad_scope(
        NetworkScope::BroadSameUser,
        decisions(ManagedEffectDecision::Allow),
    );
    legacy.managed_policy = ManagedPolicyCoverage::Unrestricted {
        policy_digest: digest(45),
    };
    assert!(
        admit_effective_mode(
            PermissionMode::FullAccess,
            PresetVersion::V1,
            &legacy,
            &MockAdmission,
        )
        .is_ok()
    );
}

#[test]
fn full_compiler_preserves_stricter_ask_and_requires_exact_approval_for_minimum_ask() {
    let mut rules = decisions(ManagedEffectDecision::Allow);
    rules[ManagedEffectClass::FsRead.tag() as usize - 1] = ManagedEffectDecision::Ask;
    let mut input = input_for_read(rules);
    assert_eq!(
        PermissionPolicyCompiler::compile(&input),
        PolicyDecision::Deny(DenyReason::ScopeOrEvidenceMismatch)
    );
    input.managed.disposition = ManagedDisposition::Ask;
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
fn closed_broad_read_requires_approval_in_ask_and_risk_modes_only() {
    let scope = broad_scope(
        NetworkScope::BroadSameUser,
        decisions(ManagedEffectDecision::Allow),
    );
    for (mode, reason) in [
        (PermissionMode::AskAlways, ApprovalReason::AskAlways),
        (
            PermissionMode::RiskBased,
            ApprovalReason::RiskOrScopeUnknown,
        ),
    ] {
        let input = input_for_scope(scope.clone(), mode);
        assert!(matches!(
            PermissionPolicyCompiler::compile(&input),
            PolicyDecision::RequireApproval { reason: actual, .. } if actual == reason
        ));
    }
    let input = input_for_scope(scope, PermissionMode::FullAccess);
    assert!(matches!(
        PermissionPolicyCompiler::compile(&input),
        PolicyDecision::Allow {
            effective_mode: PermissionMode::FullAccess,
            ..
        }
    ));
}

#[test]
fn closed_narrow_held_safe_read_keeps_risk_based_auto_admission() {
    let input = input_for_read(decisions(ManagedEffectDecision::Allow));
    assert!(matches!(
        PermissionPolicyCompiler::compile(&input),
        PolicyDecision::Allow {
            effective_mode: PermissionMode::RiskBased,
            ..
        }
    ));
}
