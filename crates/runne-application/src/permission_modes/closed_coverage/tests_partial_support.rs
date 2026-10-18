use crate::permission_modes::closed_coverage_test_support as support;

use crate::permission_modes::{
    CompositeEffectScope, CompositeScopeDigest, ContainmentStrategy, DenyReason,
    EffectiveModeState, FilesystemPermission, ManagedDisposition, NetworkScope, PermissionMode,
    PermissionPolicyCompiler, PolicyDecision,
};
use crate::project_trust::{ManagedEffectClass, ManagedEffectDecision};
use std::collections::BTreeSet;

fn partial_scope(rules: [ManagedEffectDecision; 6]) -> CompositeEffectScope {
    let mut scope = support::broad_scope(NetworkScope::None, rules);
    scope.containment = ContainmentStrategy::SameUserCompositeV2;
    scope.filesystem.permissions = BTreeSet::from([
        FilesystemPermission::Read,
        FilesystemPermission::Create,
        FilesystemPermission::Write,
    ]);
    scope
}

fn widened_denied_request(
    invalidate_evidence: bool,
) -> crate::permission_modes::PolicyEvaluationInput {
    let mut rules = support::decisions(ManagedEffectDecision::Allow);
    rules[ManagedEffectClass::FsDelete.tag() as usize - 1] = ManagedEffectDecision::Deny;
    let partial = partial_scope(rules);
    let mut input = support::input_for_scope(partial, PermissionMode::FullAccess);
    let mut widened = input.invocation.composite_scope.clone();
    widened
        .filesystem
        .permissions
        .insert(FilesystemPermission::Delete);
    let digest = widened.digest().unwrap();
    input.invocation.composite_scope = widened.clone();
    input.invocation.candidate_binding.composite_scope_digest = digest;
    input.invocation.candidate_binding.containment_version = widened.containment;
    input.invocation.candidate_binding.relevant_policy_digest =
        widened.managed_policy.policy_digest();
    input.managed.scope_digest = if invalidate_evidence {
        CompositeScopeDigest::from_bytes([0; 32])
    } else {
        digest
    };
    input.managed.policy_digest = widened.managed_policy.policy_digest();
    input.managed.disposition = ManagedDisposition::Allow;
    input.invocation.native_admission = None;
    input.effective =
        EffectiveModeState::NotReady(crate::permission_modes::NotReadyReason::NativeContainment);
    input
}

#[test]
fn authentic_denied_right_precedes_readiness_and_attenuation_failures() {
    let input = widened_denied_request(false);
    assert_eq!(
        PermissionPolicyCompiler::compile(&input),
        PolicyDecision::Deny(DenyReason::ManagedPolicy)
    );
}

#[test]
fn invalid_exact_evidence_remains_a_scope_mismatch_before_managed_deny() {
    let input = widened_denied_request(true);
    assert_eq!(
        PermissionPolicyCompiler::compile(&input),
        PolicyDecision::Deny(DenyReason::ScopeOrEvidenceMismatch)
    );
}
