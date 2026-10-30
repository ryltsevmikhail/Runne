use crate::project_trust::ManagedEffectDecision;

use super::{
    ApprovalReason, ApprovalUnit, DenyReason, ManagedDisposition, PermissionMode, PolicyDecision,
    PolicyEvaluationInput, PresetVersion,
};
use crate::permission_modes::{
    compiler_rules::{binding_matches, effect_is_in_scope, should_auto_admit},
    composite::{CompositeEffectScope, ContainmentStrategy, ManagedPolicyCoverage},
    readiness::EffectiveModeState,
    resource::PermissionAction,
};

pub(crate) fn check_minimum(
    scope: &CompositeEffectScope,
    action: PermissionAction,
    supplied: ManagedDisposition,
) -> Result<(), DenyReason> {
    let ManagedPolicyCoverage::Closed(coverage) = &scope.managed_policy else {
        return Ok(());
    };
    if !coverage.supports_scope(scope) {
        return Err(DenyReason::ScopeOrEvidenceMismatch);
    }
    if action == PermissionAction::ProcessStart
        && scope.containment == ContainmentStrategy::WorkspaceBoundV1
        && !crate::permission_modes::compiler_rules::workspace_process_scope(scope)
    {
        return Err(DenyReason::OutsideAdmittedScope);
    }
    let minimum = coverage.scope_minimum_disposition(scope);
    if minimum == ManagedEffectDecision::Deny || supplied == ManagedDisposition::Deny {
        return Err(DenyReason::ManagedPolicy);
    }
    if minimum == ManagedEffectDecision::Ask && supplied == ManagedDisposition::Allow {
        return Err(DenyReason::ScopeOrEvidenceMismatch);
    }
    Ok(())
}

pub(super) fn compile_legacy(input: &PolicyEvaluationInput) -> PolicyDecision {
    if input.selection.preset_version != PresetVersion::V1 {
        return PolicyDecision::Deny(DenyReason::UnsupportedPreset);
    }
    if input
        .selection
        .expires_at_unix_ms
        .is_some_and(|expiry| input.now_unix_ms >= expiry)
    {
        return PolicyDecision::Deny(DenyReason::Expired);
    }
    if input.selection.scope != input.effective_scope.permission_scope
        || input.selection.scope != input.invocation.composite_scope.permission_scope
        || !input
            .invocation
            .composite_scope
            .is_attenuated_from(&input.effective_scope)
    {
        return PolicyDecision::Deny(DenyReason::ScopeOrEvidenceMismatch);
    }
    let (effective_mode, mode_receipt) = match &input.effective {
        EffectiveModeState::Ready(ready) => (ready.mode(), ready.mode_readiness()),
        EffectiveModeState::NotReady(_) => {
            return PolicyDecision::Deny(DenyReason::EffectiveModeNotReady);
        }
    };
    if effective_mode != input.selection.selected_mode
        || match &input.effective {
            EffectiveModeState::Ready(ready) => {
                ready.preset_version() != input.selection.preset_version
            }
            _ => true,
        }
        || mode_receipt.scope_digest()
            != match input.effective_scope.digest() {
                Ok(digest) => digest,
                Err(_) => return PolicyDecision::Deny(DenyReason::ScopeOrEvidenceMismatch),
            }
        || mode_receipt.managed_policy_digest()
            != input.effective_scope.managed_policy.policy_digest()
        || mode_receipt
            .platform_handle_id()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || input.effective_scope.managed_policy != input.invocation.composite_scope.managed_policy
    {
        return PolicyDecision::Deny(DenyReason::ScopeOrEvidenceMismatch);
    }
    let scope_digest = match input.invocation.composite_scope.digest() {
        Ok(digest) => digest,
        Err(_) => return PolicyDecision::Deny(DenyReason::ScopeOrEvidenceMismatch),
    };
    if input.managed.scope_digest != scope_digest
        || input.managed.policy_digest
            != input
                .invocation
                .composite_scope
                .managed_policy
                .policy_digest()
        || !binding_matches(
            &input.invocation.candidate_binding,
            input.invocation.action,
            &input.invocation.composite_scope,
            scope_digest,
        )
    {
        return PolicyDecision::Deny(DenyReason::ScopeOrEvidenceMismatch);
    }
    if let Err(reason) = check_minimum(
        &input.invocation.composite_scope,
        input.invocation.action,
        input.managed.disposition,
    ) {
        return PolicyDecision::Deny(reason);
    }
    if input.managed.disposition == ManagedDisposition::Deny {
        return PolicyDecision::Deny(DenyReason::ManagedPolicy);
    }
    if input.invocation.candidate_binding.expires_at_unix_ms <= input.now_unix_ms {
        return PolicyDecision::Deny(DenyReason::Expired);
    }
    let Some(native) = input.invocation.native_admission else {
        return PolicyDecision::Deny(DenyReason::OutsideAdmittedScope);
    };
    if native.scope_digest() != scope_digest
        || native.managed_policy_digest() != input.managed.policy_digest
        || native.containment() != input.invocation.composite_scope.containment
        || native
            .platform_handle_id()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return PolicyDecision::Deny(DenyReason::ScopeOrEvidenceMismatch);
    }
    if !effect_is_in_scope(
        input.invocation.action,
        &input.invocation.resource,
        &input.invocation.composite_scope,
    ) {
        return PolicyDecision::Deny(DenyReason::OutsideAdmittedScope);
    }
    let reason = if input.managed.disposition == ManagedDisposition::Ask {
        Some(ApprovalReason::ManagedAsk)
    } else if should_auto_admit(
        effective_mode,
        input.invocation.action,
        &input.invocation.resource,
        &input.invocation.composite_scope,
    ) {
        None
    } else {
        Some(if effective_mode == PermissionMode::AskAlways {
            ApprovalReason::AskAlways
        } else {
            ApprovalReason::RiskOrScopeUnknown
        })
    };
    let binding_digest = input.invocation.candidate_binding.digest();
    if let Some(reason) = reason {
        if input
            .invocation
            .approved_binding
            .as_ref()
            .is_some_and(|approved| {
                approved.is_compatible_with(&input.invocation.candidate_binding, input.now_unix_ms)
            })
        {
            return super::allow(effective_mode, native, scope_digest, binding_digest);
        }
        return PolicyDecision::RequireApproval {
            reason,
            unit: ApprovalUnit::Invocation,
            approval_binding_digest: binding_digest,
        };
    }
    super::allow(effective_mode, native, scope_digest, binding_digest)
}
