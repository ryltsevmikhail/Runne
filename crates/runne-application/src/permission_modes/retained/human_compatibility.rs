//! Structural proof correlation and componentwise retained-policy comparisons.

use runne_domain::id::IntegrityDigest;

use crate::{
    permission_modes::{
        PermissionAction,
        composite::{CompositeEffectScope, ManagedPolicyCoverage},
        local_command_binding::LocalCommandPermissionBindingV1,
    },
    project_trust::{
        ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, managed_effect_policy_digest_v2,
    },
};

use super::{
    approval::RetainedHumanEvidenceV1,
    model::{
        RETAINED_POLICY_EVALUATOR_VERSION_V1, RETAINED_RELEVANT_SEMANTICS_VERSION_V1,
        RetainedCurrentFactsV1, RetainedNotEvaluableReasonV1, RetainedOriginalContextV1,
    },
    provided_classes::retained_provided_classes,
    semantics::{RetainedRelevantSemanticsV1, retained_relevant_semantics},
};

pub(super) fn same_nonmanaged_scope_shape(
    left: &CompositeEffectScope,
    right: &CompositeEffectScope,
) -> bool {
    left.permission_scope == right.permission_scope
        && left.filesystem == right.filesystem
        && left.network == right.network
        && left.children == right.children
        && left.budget == right.budget
        && left.lifetime_ms == right.lifetime_ms
        && left.containment == right.containment
        && left.protected_control_plane_policy_digest == right.protected_control_plane_policy_digest
}

fn same_trust_owner(
    proof: ProjectTrustEffectPolicySnapshot,
    original: ProjectTrustEffectPolicySnapshot,
    current: ProjectTrustEffectPolicySnapshot,
) -> bool {
    proof.record.instance_epoch == original.record.instance_epoch
        && proof.record.status == original.record.status
        && proof.record.managed_deny_mask == original.record.managed_deny_mask
        && proof.record.instance_epoch == current.record.instance_epoch
        && proof.record.status == current.record.status
        && proof.record.managed_deny_mask == current.record.managed_deny_mask
}

fn proof_binding_matches(
    original: &LocalCommandPermissionBindingV1,
    proof: &RetainedHumanEvidenceV1,
) -> bool {
    let expected = original.approval();
    let actual = proof.binding();
    let scope_digest = proof.scope().digest().ok();
    scope_digest.is_some_and(|scope_digest| {
        actual.action == expected.action
            && actual.normalized_arguments_digest == expected.normalized_arguments_digest
            && actual.tool_schema_digest == expected.tool_schema_digest
            && actual.principal_id == expected.principal_id
            && actual.invocation == expected.invocation
            && actual.target_identity_digest == expected.target_identity_digest
            && actual.target_version == expected.target_version
            && actual.environment_digest == expected.environment_digest
            && actual.cwd_identity_digest == expected.cwd_identity_digest
            && actual.executable_digest == expected.executable_digest
            && actual.composite_scope_digest == scope_digest
            && actual.containment_version == expected.containment_version
            && actual.relevant_policy_digest == proof.scope().managed_policy.policy_digest()
            && actual.expires_at_unix_ms == expected.expires_at_unix_ms
    })
}

fn validate_proof_data(
    original: &LocalCommandPermissionBindingV1,
    context: &RetainedOriginalContextV1,
    proof: &RetainedHumanEvidenceV1,
) -> Result<RetainedRelevantSemanticsV1, RetainedNotEvaluableReasonV1> {
    let provided = retained_provided_classes(original.scope())
        .ok_or(RetainedNotEvaluableReasonV1::UnsupportedScope)?;
    let proof_provided = retained_provided_classes(proof.scope())
        .ok_or(RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent)?;
    let project = ProjectTrustProjectId::from_bytes(*original.project_id().as_bytes());
    let policy_digest = managed_effect_policy_digest_v2(project, &proof.snapshot())
        .map(IntegrityDigest::from_bytes)
        .ok_or(RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent)?;
    let coverage = ManagedPolicyCoverage::from_closed_snapshot(project, &proof.snapshot())
        .ok_or(RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent)?;
    let semantics = retained_relevant_semantics(
        &proof.snapshot(),
        provided,
        1,
        crate::project_trust::FROZEN_POLICY_VERSION,
        crate::project_trust::LOCAL_COMMAND_POLICY_VERSION,
    )
    .ok_or(RetainedNotEvaluableReasonV1::UnsupportedVersion)?;
    let original_snapshot = original.closed_rules_snapshot();
    if proof.original_binding_digest() != original.digest()
        || context.original_binding_digest != original.digest()
        || proof.project_id() != original.project_id()
        || proof_provided != provided
        || !same_nonmanaged_scope_shape(proof.scope(), original.scope())
        || proof.scope().validate().is_err()
        || coverage != proof.scope().managed_policy
        || policy_digest != proof.app_policy_digest()
        || proof.binding().action != PermissionAction::ProcessStart
        || proof.binding_digest() != proof.binding().digest()
        || !proof_binding_matches(original, proof)
        || proof.accepted_by() != &original.approval().principal_id
        || proof.accepted_at_unix_ms() <= 0
        || proof.expires_at_unix_ms() <= proof.accepted_at_unix_ms()
        || proof.expires_at_unix_ms() > original.approval().expires_at_unix_ms
        || proof.expires_at_unix_ms() > context.invocation_deadline_unix_ms
        || semantics.digest != proof.relevant_semantics_digest()
        || !same_trust_owner(proof.snapshot(), original_snapshot, original_snapshot)
    {
        return Err(RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent);
    }
    Ok(semantics)
}

pub(super) fn validate_original_human(
    original: &LocalCommandPermissionBindingV1,
    context: &RetainedOriginalContextV1,
    proof: &RetainedHumanEvidenceV1,
) -> Result<RetainedRelevantSemanticsV1, RetainedNotEvaluableReasonV1> {
    let semantics = validate_proof_data(original, context, proof)?;
    if proof.binding() != original.approval()
        || proof.scope() != original.scope()
        || proof.snapshot() != original.closed_rules_snapshot()
        || proof.app_policy_digest() != original.closed_rules_digest()
        || proof.accepted_at_unix_ms() > context.admission_clock.wall_unix_ms
    {
        return Err(RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent);
    }
    Ok(semantics)
}

pub(super) fn validate_selected_human(
    original: &LocalCommandPermissionBindingV1,
    context: &RetainedOriginalContextV1,
    current: &RetainedCurrentFactsV1,
    proof: &RetainedHumanEvidenceV1,
) -> Result<RetainedRelevantSemanticsV1, RetainedNotEvaluableReasonV1> {
    let semantics = validate_proof_data(original, context, proof)?;
    if !same_trust_owner(
        proof.snapshot(),
        original.closed_rules_snapshot(),
        current.snapshot,
    ) || proof.accepted_at_unix_ms() > current.observed_clock.wall_unix_ms
    {
        return Err(RetainedNotEvaluableReasonV1::ApprovalEvidenceInconsistent);
    }
    Ok(semantics)
}

pub(super) fn semantics_equal(
    proof: &RetainedRelevantSemanticsV1,
    current: &RetainedRelevantSemanticsV1,
) -> bool {
    proof.evaluator_version == RETAINED_POLICY_EVALUATOR_VERSION_V1
        && current.evaluator_version == RETAINED_POLICY_EVALUATOR_VERSION_V1
        && proof.semantics_version == RETAINED_RELEVANT_SEMANTICS_VERSION_V1
        && current.semantics_version == RETAINED_RELEVANT_SEMANTICS_VERSION_V1
        && proof.evaluator_version == current.evaluator_version
        && proof.semantics_version == current.semantics_version
        && proof.preset_version == current.preset_version
        && proof.source_policy_version == current.source_policy_version
        && proof.command_policy_version == current.command_policy_version
        && proof.provided == current.provided
        && proof.decisions == current.decisions
        && proof.digest == current.digest
}
