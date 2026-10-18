//! Ordered pure policy compatibility for one frozen original invocation.

use runne_domain::id::IntegrityDigest;

use crate::{
    permission_modes::{
        PermissionAction,
        compiler_rules::{effect_is_in_scope, should_auto_admit},
        local_command_binding::LocalCommandPermissionBindingV1,
        resource::ResourceFacts,
    },
    project_trust::ManagedEffectDecision,
};

use super::{
    approval::RetainedHumanEvidenceV1,
    bounds,
    current_facts::validate_current_structure,
    human_compatibility::{semantics_equal, validate_original_human, validate_selected_human},
    identity::{validate_current_identity, validate_original_context},
    model::{
        RetainedAdmissionEvidenceV1, RetainedApprovalRequirementV1, RetainedNotEvaluableReasonV1,
        RetainedPolicyEvaluationV1, RetainedPolicyInputV1, RetainedReleaseRequirementsV1,
    },
    phase::{PhaseStatus, observe_phase},
    provided_classes::retained_provided_classes,
    semantics::{RetainedRelevantSemanticsV1, retained_relevant_semantics},
};

fn not_evaluable(reason: RetainedNotEvaluableReasonV1) -> RetainedPolicyEvaluationV1 {
    RetainedPolicyEvaluationV1::NotEvaluable(reason)
}

fn nonzero(digest: &IntegrityDigest) -> bool {
    digest.as_bytes().iter().any(|byte| *byte != 0)
}

fn bounded_resource_size(resource: &ResourceFacts) -> Option<usize> {
    let Some(path) = resource.resolved_path.as_ref() else {
        return Some(0);
    };
    if path.components.len() > 256 || !nonzero(&path.root_identity) {
        return None;
    }
    let mut path_bytes = path.components.len().saturating_sub(1);
    for component in &path.components {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains('/')
            || component.contains('\\')
            || component.chars().any(char::is_control)
            || component.len() > 255
        {
            return None;
        }
        path_bytes = path_bytes.checked_add(component.len())?;
    }
    (path_bytes <= 4096).then_some(32 + path_bytes)
}

fn original_resource_identity_is_complete(original: &LocalCommandPermissionBindingV1) -> bool {
    let binding = original.approval();
    binding.target_version > 0
        && binding
            .executable_digest
            .is_some_and(|digest| nonzero(&digest))
        && nonzero(&binding.normalized_arguments_digest)
        && nonzero(&binding.tool_schema_digest)
        && nonzero(&binding.target_identity_digest)
        && nonzero(&binding.environment_digest)
        && nonzero(&binding.cwd_identity_digest)
}

fn human_usable(
    proof: &RetainedHumanEvidenceV1,
    semantics: &RetainedRelevantSemanticsV1,
    current: &RetainedRelevantSemanticsV1,
    now: i64,
    before_start: Option<i64>,
) -> bool {
    semantics_equal(semantics, current)
        && proof.accepted_at_unix_ms() <= now
        && before_start.is_none_or(|start| proof.accepted_at_unix_ms() <= start)
        && now < proof.expires_at_unix_ms()
        && now < proof.binding().expires_at_unix_ms
}

fn approval_gap_result(
    phase: PhaseStatus,
    original_digest: IntegrityDigest,
    semantics_digest: IntegrityDigest,
) -> RetainedPolicyEvaluationV1 {
    if phase == PhaseStatus::BeforeGo {
        RetainedPolicyEvaluationV1::RequireApproval {
            requirement: RetainedApprovalRequirementV1::ExactHumanApproval,
            original_binding_digest: original_digest,
            current_semantics_digest: semantics_digest,
        }
    } else {
        RetainedPolicyEvaluationV1::StopRequired {
            requirement: RetainedApprovalRequirementV1::StopRequired,
            original_binding_digest: original_digest,
            current_semantics_digest: semantics_digest,
        }
    }
}

fn stop_result(
    original_digest: IntegrityDigest,
    semantics_digest: IntegrityDigest,
) -> RetainedPolicyEvaluationV1 {
    RetainedPolicyEvaluationV1::StopRequired {
        requirement: RetainedApprovalRequirementV1::StopRequired,
        original_binding_digest: original_digest,
        current_semantics_digest: semantics_digest,
    }
}

pub(super) fn evaluate(input: &RetainedPolicyInputV1<'_>) -> RetainedPolicyEvaluationV1 {
    let Some(context) = input.original_context else {
        return not_evaluable(RetainedNotEvaluableReasonV1::MissingOriginalContext);
    };
    if matches!(input.admission, RetainedAdmissionEvidenceV1::Pending) {
        return not_evaluable(RetainedNotEvaluableReasonV1::MissingAdmission);
    }
    let Some(resource_size) = bounded_resource_size(input.resource) else {
        return not_evaluable(RetainedNotEvaluableReasonV1::CurrentFactsInconsistent);
    };
    if !bounds::evaluate_input_within_bounds(input, resource_size) {
        return not_evaluable(RetainedNotEvaluableReasonV1::CurrentFactsInconsistent);
    }
    if let Err(reason) = validate_original_context(input.original, context) {
        return not_evaluable(reason);
    }
    let original_digest = input.original.digest();
    if input.action != PermissionAction::ProcessStart
        || input.original_identity_candidate != input.original.approval()
        || input.current.candidate != *input.original.approval()
    {
        return not_evaluable(RetainedNotEvaluableReasonV1::OriginalIdentityMismatch);
    }
    if let Err(reason) = validate_current_structure(input.current) {
        return not_evaluable(reason);
    }
    if let Err(reason) = validate_current_identity(input.original, context, input.current) {
        return not_evaluable(reason);
    }
    let Some(provided) = retained_provided_classes(input.original.scope()) else {
        return not_evaluable(RetainedNotEvaluableReasonV1::UnsupportedScope);
    };
    let Some(current_semantics) = retained_relevant_semantics(
        &input.current.snapshot,
        provided,
        input.current.selection.preset_version.as_u16(),
        input.current.coordinates.source_policy_version,
        input.current.coordinates.command_policy_version,
    ) else {
        return not_evaluable(RetainedNotEvaluableReasonV1::UnsupportedVersion);
    };
    let original_human = match input.admission {
        RetainedAdmissionEvidenceV1::Human(proof) => {
            match validate_original_human(input.original, context, proof) {
                Ok(semantics) => Some((proof, semantics)),
                Err(reason) => return not_evaluable(reason),
            }
        }
        RetainedAdmissionEvidenceV1::Auto => None,
        RetainedAdmissionEvidenceV1::Pending => {
            return not_evaluable(RetainedNotEvaluableReasonV1::MissingAdmission);
        }
    };
    let selected_human = match input.selected_human_candidate {
        Some(proof) => match validate_selected_human(input.original, context, input.current, proof)
        {
            Ok(semantics) => Some((proof, semantics)),
            Err(reason) => return not_evaluable(reason),
        },
        None => None,
    };
    let phase = match observe_phase(input.original, context, input.current, input.phase) {
        Ok(status) => status,
        Err(reason) => return not_evaluable(reason),
    };
    if !original_resource_identity_is_complete(input.original) || !input.resource.executable {
        return not_evaluable(RetainedNotEvaluableReasonV1::CurrentFactsInconsistent);
    }
    if !effect_is_in_scope(input.action, input.resource, input.original.scope()) {
        return RetainedPolicyEvaluationV1::Denied;
    }
    let decision_deny = current_semantics
        .decisions
        .iter()
        .zip(current_semantics.provided)
        .any(|(decision, is_provided)| {
            is_provided && *decision == Some(ManagedEffectDecision::Deny)
        });
    if decision_deny {
        return RetainedPolicyEvaluationV1::Denied;
    }
    let managed_ask = current_semantics
        .decisions
        .iter()
        .zip(current_semantics.provided)
        .any(|(decision, is_provided)| {
            is_provided && *decision == Some(ManagedEffectDecision::Ask)
        });
    let now = input.current.observed_clock.wall_unix_ms;
    let start_wall = input
        .phase
        .runtime_start
        .map(|start| start.wall_start_unix_ms);
    let original_human_usable = original_human.is_some_and(|(proof, semantics)| {
        human_usable(proof, &semantics, &current_semantics, now, start_wall)
    });
    let selected_human_usable = selected_human.is_some_and(|(proof, semantics)| {
        human_usable(proof, &semantics, &current_semantics, now, start_wall)
    });
    let has_matching_human = original_human_usable || selected_human_usable;
    let auto_admitted = should_auto_admit(
        input.current.selection.selected_mode,
        input.action,
        input.resource,
        input.original.scope(),
    );
    if phase == PhaseStatus::StopRequired {
        return stop_result(original_digest, current_semantics.digest);
    }
    if (managed_ask || !auto_admitted) && !has_matching_human {
        return approval_gap_result(phase, original_digest, current_semantics.digest);
    }
    let Ok(current_scope_digest) = input.current.scope.digest() else {
        return not_evaluable(RetainedNotEvaluableReasonV1::CurrentFactsInconsistent);
    };
    RetainedPolicyEvaluationV1::PolicyCompatible {
        current_semantics,
        original_binding_digest: original_digest,
        current_scope_digest,
        release_requirements: RetainedReleaseRequirementsV1::unresolved(),
    }
}
