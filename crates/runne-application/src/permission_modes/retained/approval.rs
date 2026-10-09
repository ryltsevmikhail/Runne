//! Checked human-evidence data. Construction never verifies durable acceptance.

use runne_api::ApiPrincipalId;
use runne_domain::id::{ApprovalId, IntegrityDigest};

use crate::project_trust::{
    ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, managed_effect_policy_digest_v2,
};

use super::super::local_command_binding::LocalCommandPermissionBindingV1;
use super::{
    super::binding::ApprovalBinding,
    super::composite::{CompositeEffectScope, ManagedPolicyCoverage},
    bounds,
    model::{
        RETAINED_POLICY_EVALUATOR_VERSION_V1, RETAINED_RELEVANT_SEMANTICS_VERSION_V1,
        RetainedNotEvaluableReasonV1, RetainedOriginalContextV1,
    },
    provided_classes::retained_provided_classes,
    semantics::retained_relevant_semantics,
};
use super::{human_compatibility::same_nonmanaged_scope_shape, identity};

/// Caller-supplied proof record and its independent policy capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedHumanEvidenceInputV1 {
    pub approval_id: ApprovalId,
    pub original_binding_digest: IntegrityDigest,
    pub binding: ApprovalBinding,
    pub binding_digest: IntegrityDigest,
    pub scope: CompositeEffectScope,
    pub snapshot: ProjectTrustEffectPolicySnapshot,
    pub project_id: runne_domain::id::ProjectId,
    pub app_policy_digest: IntegrityDigest,
    pub evaluator_version: u16,
    pub semantics_version: u16,
    pub preset_version: u16,
    pub source_policy_version: u64,
    pub command_policy_version: u64,
    pub relevant_semantics_digest: IntegrityDigest,
    pub accepted_by: ApiPrincipalId,
    pub accepted_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

/// Checked data linked to an original invocation; not VerifiedHumanApproval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedHumanEvidenceV1 {
    approval_id: ApprovalId,
    original_binding_digest: IntegrityDigest,
    binding: ApprovalBinding,
    binding_digest: IntegrityDigest,
    scope: CompositeEffectScope,
    snapshot: ProjectTrustEffectPolicySnapshot,
    project_id: runne_domain::id::ProjectId,
    app_policy_digest: IntegrityDigest,
    relevant_semantics_digest: IntegrityDigest,
    accepted_by: ApiPrincipalId,
    accepted_at_unix_ms: i64,
    expires_at_unix_ms: i64,
}

impl RetainedHumanEvidenceV1 {
    /// Checks bounded evidence consistency against the frozen original binding.
    /// It does not establish a human action, durable Store record, or live authority.
    pub fn checked(
        original: &LocalCommandPermissionBindingV1,
        context: &RetainedOriginalContextV1,
        input: RetainedHumanEvidenceInputV1,
    ) -> Result<Self, RetainedNotEvaluableReasonV1> {
        if !bounds::original_within_bounds(original) || !bounds::human_input_within_bounds(&input) {
            return Err(RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent);
        }
        identity::validate_original_context(original, context)
            .map_err(|_| RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent)?;
        let trust_project = ProjectTrustProjectId::from_bytes(*input.project_id.as_bytes());
        let own_app_digest = managed_effect_policy_digest_v2(trust_project, &input.snapshot)
            .map(IntegrityDigest::from_bytes)
            .ok_or(RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent)?;
        let own_coverage =
            ManagedPolicyCoverage::from_closed_snapshot(trust_project, &input.snapshot)
                .ok_or(RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent)?;
        let own_scope_digest = input
            .scope
            .digest()
            .map_err(|_| RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent)?;
        let provided = retained_provided_classes(&input.scope)
            .ok_or(RetainedNotEvaluableReasonV1::UnsupportedScope)?;
        let semantics = retained_relevant_semantics(
            &input.snapshot,
            provided,
            input.preset_version,
            input.source_policy_version,
            input.command_policy_version,
        )
        .ok_or(RetainedNotEvaluableReasonV1::UnsupportedVersion)?;
        let original_binding = original.approval();
        let own_snapshot = input.snapshot.record;
        let original_snapshot = original.closed_rules_snapshot().record;
        if input.original_binding_digest != original.digest()
            || runne_domain::id::validate_uuid_v7_bytes(input.approval_id.as_bytes()).is_err()
            || context.original_binding_digest != original.digest()
            || input.project_id != original.project_id()
            || input.evaluator_version != RETAINED_POLICY_EVALUATOR_VERSION_V1
            || input.semantics_version != RETAINED_RELEVANT_SEMANTICS_VERSION_V1
            || own_app_digest != input.app_policy_digest
            || own_coverage != input.scope.managed_policy
            || input.scope.validate().is_err()
            || !same_nonmanaged_scope_shape(&input.scope, original.scope())
            || own_scope_digest != input.binding.composite_scope_digest
            || input.binding.action != original_binding.action
            || input.binding.normalized_arguments_digest
                != original_binding.normalized_arguments_digest
            || input.binding.tool_schema_digest != original_binding.tool_schema_digest
            || input.binding.principal_id != original_binding.principal_id
            || input.binding.invocation != original_binding.invocation
            || input.binding.target_identity_digest != original_binding.target_identity_digest
            || input.binding.target_version != original_binding.target_version
            || input.binding.environment_digest != original_binding.environment_digest
            || input.binding.cwd_identity_digest != original_binding.cwd_identity_digest
            || input.binding.executable_digest != original_binding.executable_digest
            || input.binding.containment_version != original_binding.containment_version
            || input.binding.expires_at_unix_ms != original_binding.expires_at_unix_ms
            || input.binding.action != crate::permission_modes::PermissionAction::ProcessStart
            || input.binding.principal_id != input.accepted_by
            || input.binding.relevant_policy_digest != input.scope.managed_policy.policy_digest()
            || input.binding_digest != input.binding.digest()
            || semantics.digest != input.relevant_semantics_digest
            || input.accepted_at_unix_ms <= 0
            || input.expires_at_unix_ms <= input.accepted_at_unix_ms
            || input.expires_at_unix_ms > input.binding.expires_at_unix_ms
            || input.expires_at_unix_ms > context.invocation_deadline_unix_ms
            || input.accepted_by != original_binding.principal_id
            || own_snapshot.instance_epoch != original_snapshot.instance_epoch
            || own_snapshot.status != original_snapshot.status
            || own_snapshot.managed_deny_mask != original_snapshot.managed_deny_mask
        {
            return Err(RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent);
        }
        Ok(Self {
            approval_id: input.approval_id,
            original_binding_digest: input.original_binding_digest,
            binding: input.binding,
            binding_digest: input.binding_digest,
            scope: input.scope,
            snapshot: input.snapshot,
            project_id: input.project_id,
            app_policy_digest: input.app_policy_digest,
            relevant_semantics_digest: input.relevant_semantics_digest,
            accepted_by: input.accepted_by,
            accepted_at_unix_ms: input.accepted_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
        })
    }

    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }
    pub const fn original_binding_digest(&self) -> IntegrityDigest {
        self.original_binding_digest
    }
    pub const fn binding(&self) -> &ApprovalBinding {
        &self.binding
    }
    pub const fn binding_digest(&self) -> IntegrityDigest {
        self.binding_digest
    }
    pub const fn scope(&self) -> &CompositeEffectScope {
        &self.scope
    }
    pub const fn snapshot(&self) -> ProjectTrustEffectPolicySnapshot {
        self.snapshot
    }
    pub const fn project_id(&self) -> runne_domain::id::ProjectId {
        self.project_id
    }
    pub const fn app_policy_digest(&self) -> IntegrityDigest {
        self.app_policy_digest
    }
    pub const fn relevant_semantics_digest(&self) -> IntegrityDigest {
        self.relevant_semantics_digest
    }
    pub const fn accepted_by(&self) -> &ApiPrincipalId {
        &self.accepted_by
    }
    pub const fn accepted_at_unix_ms(&self) -> i64 {
        self.accepted_at_unix_ms
    }
    pub const fn expires_at_unix_ms(&self) -> i64 {
        self.expires_at_unix_ms
    }
}
