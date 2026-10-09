//! Frozen original and independently observed current owner-coordinate checks.

use runne_domain::id::IntegrityDigest;

use crate::{
    permission_modes::{
        PermissionAction, composite::ManagedPolicyCoverage,
        local_command_binding::LocalCommandPermissionBindingV1, model::PresetVersion,
    },
    project_trust::{ProjectTrustProjectId, managed_effect_policy_digest_v2},
};

use super::{
    current_facts::{RetainedBoundaryObservationV1, RetainedExecutionObservationV1},
    human_compatibility::same_nonmanaged_scope_shape,
    model::{
        RETAINED_SOURCE_CAPTURE_VERSION_V1, RetainedClockObservationV1, RetainedCurrentFactsV1,
        RetainedNotEvaluableReasonV1, RetainedOriginalContextV1, RetainedOwnerCoordinatesV1,
    },
};

pub(super) fn coordinates_well_formed(value: &RetainedOwnerCoordinatesV1) -> bool {
    !value.runtime_authority_id.is_empty()
        && value.runtime_authority_id.len() <= 256
        && !value.runtime_authority_id.chars().any(char::is_control)
        && value.project_version > 0
        && value.workspace_version > 0
        && value.admitted_root_version > 0
        && value.claim_stream_version > 0
        && value.assignment.node_epoch > 0
        && value.assignment.fence.0 > 0
        && !value.assignment.node_id.0.is_empty()
        && value.assignment.node_id.0.len() <= 256
        && !value.assignment.node_id.0.chars().any(char::is_control)
        && runne_domain::id::validate_uuid_v7_bytes(value.workspace_id.as_bytes()).is_ok()
        && runne_domain::id::validate_uuid_v7_bytes(value.project_id.as_bytes()).is_ok()
        && runne_domain::id::validate_uuid_v7_bytes(value.assignment.taskrun_id.as_bytes()).is_ok()
        && runne_domain::id::validate_uuid_v7_bytes(value.assignment.attempt_id.as_bytes()).is_ok()
        && runne_domain::id::validate_uuid_v7_bytes(value.invocation_id.as_bytes()).is_ok()
        && value.root_generation > 0
        && value.protected_generation > 0
        && !value.native_boundary_owner_id.is_empty()
        && value.native_boundary_owner_id.len() <= 256
        && !value.native_boundary_owner_id.chars().any(char::is_control)
        && value.native_boundary_owner_epoch > 0
        && value.source_policy_version == crate::project_trust::FROZEN_POLICY_VERSION
        && value.command_policy_version == crate::project_trust::LOCAL_COMMAND_POLICY_VERSION
        && value.trust_record.instance_epoch > 0
        && value.trust_record.managed_deny_mask & !0x7f == 0
        && value
            .held_root_identity_digest
            .as_bytes()
            .iter()
            .any(|byte| *byte != 0)
        && value
            .protected_policy_digest
            .as_bytes()
            .iter()
            .any(|byte| *byte != 0)
}

pub(super) const fn clock_well_formed(value: RetainedClockObservationV1) -> bool {
    value.epoch > 0 && value.wall_unix_ms > 0
}

pub(super) fn validate_original_context(
    original: &LocalCommandPermissionBindingV1,
    context: &RetainedOriginalContextV1,
) -> Result<(), RetainedNotEvaluableReasonV1> {
    if !super::bounds::original_within_bounds(original)
        || !super::bounds::original_context_within_bounds(context)
    {
        return Err(RetainedNotEvaluableReasonV1::OriginalContextInconsistent);
    }
    let scope = original.scope();
    let approval = original.approval();
    let coordinates = &context.coordinates;
    let project = ProjectTrustProjectId::from_bytes(*original.project_id().as_bytes());
    let original_snapshot = original.closed_rules_snapshot();
    let policy_digest = managed_effect_policy_digest_v2(project, &original_snapshot)
        .map(IntegrityDigest::from_bytes)
        .ok_or(RetainedNotEvaluableReasonV1::OriginalContextInconsistent)?;
    let coverage = ManagedPolicyCoverage::from_closed_snapshot(project, &original_snapshot)
        .ok_or(RetainedNotEvaluableReasonV1::OriginalContextInconsistent)?;
    let scope_digest = scope
        .digest()
        .map_err(|_| RetainedNotEvaluableReasonV1::OriginalContextInconsistent)?;
    if context.original_binding_digest != original.digest()
        || context.capture_format_version != RETAINED_SOURCE_CAPTURE_VERSION_V1
        || context.source_record_version != RETAINED_SOURCE_CAPTURE_VERSION_V1
        || original.closed_rules_encoder_version() != 2
        || original.selection().preset_version != PresetVersion::V1
        || !coordinates_well_formed(coordinates)
        || !clock_well_formed(context.admission_clock)
        || coordinates.runtime_authority_id != scope.permission_scope.runtime_authority_id.0
        || coordinates.principal_id != scope.permission_scope.principal_id
        || coordinates.workspace_id != scope.permission_scope.workspace_id
        || coordinates.project_id != original.project_id()
        || coordinates.project_version != original.project_version()
        || coordinates.workspace_version != original.workspace_version()
        || coordinates.admitted_root_version != original.admitted_root_version()
        || coordinates.held_root_identity_digest != original.held_root_identity_digest()
        || coordinates.assignment != *original.assignment()
        || coordinates.claim_stream_version != original.claim_stream_version()
        || coordinates.invocation_id != original.invocation_id()
        || coordinates.protected_policy_digest != scope.protected_control_plane_policy_digest
        || coordinates.trust_record != original_snapshot.record
        || coordinates.source_policy_version != crate::project_trust::FROZEN_POLICY_VERSION
        || coordinates.command_policy_version != crate::project_trust::LOCAL_COMMAND_POLICY_VERSION
        || context.selection_expiry_unix_ms != original.selection().expires_at_unix_ms
        || context.invocation_deadline_unix_ms != approval.expires_at_unix_ms
        || context.invocation_deadline_unix_ms <= context.admission_clock.wall_unix_ms
        || context
            .selection_expiry_unix_ms
            .is_some_and(|expiry| expiry <= context.admission_clock.wall_unix_ms)
        || !original_snapshot.is_valid()
        || original.closed_rules_digest() != policy_digest
        || scope.managed_policy != coverage
        || approval.action != PermissionAction::ProcessStart
        || approval.composite_scope_digest != scope_digest
        || approval.containment_version != scope.containment
        || approval.relevant_policy_digest != scope.managed_policy.policy_digest()
        || IntegrityDigest::from_bytes(original.command().intent_digest())
            != original.command_intent_digest()
    {
        return Err(RetainedNotEvaluableReasonV1::OriginalContextInconsistent);
    }
    Ok(())
}

pub(super) fn validate_current_identity(
    original: &LocalCommandPermissionBindingV1,
    context: &RetainedOriginalContextV1,
    current: &RetainedCurrentFactsV1,
) -> Result<(), RetainedNotEvaluableReasonV1> {
    let original_coordinates = &context.coordinates;
    let coordinates = &current.coordinates;
    let Some(observation) = current.observation_context.as_ref() else {
        return Err(RetainedNotEvaluableReasonV1::MissingCurrentObservation);
    };
    if observation.format_version != 1 {
        return Err(RetainedNotEvaluableReasonV1::UnsupportedVersion);
    }
    if !coordinates_well_formed(coordinates)
        || observation.original_binding_digest != original.digest()
        || current.original_binding_digest != original.digest()
        || observation.authorization_revision != current.selection.authorization_revision
        || observation.current_snapshot_digest != current.app_policy_digest
        || observation.native_boundary_owner_id != coordinates.native_boundary_owner_id
        || observation.native_boundary_owner_epoch != coordinates.native_boundary_owner_epoch
        || coordinates.trust_record != current.snapshot.record
        || current.project_id != original.project_id()
        || coordinates.project_id != original_coordinates.project_id
        || coordinates.workspace_id != original_coordinates.workspace_id
        || coordinates.runtime_authority_id != original_coordinates.runtime_authority_id
        || coordinates.principal_id != original_coordinates.principal_id
        || coordinates.project_version != original_coordinates.project_version
        || coordinates.workspace_version != original_coordinates.workspace_version
        || coordinates.admitted_root_version != original_coordinates.admitted_root_version
        || coordinates.held_root_identity_digest != original_coordinates.held_root_identity_digest
        || coordinates.assignment != original_coordinates.assignment
        || coordinates.claim_stream_version != original_coordinates.claim_stream_version
        || coordinates.invocation_id != original_coordinates.invocation_id
        || coordinates.protected_policy_digest != original_coordinates.protected_policy_digest
        || coordinates.protected_generation != original_coordinates.protected_generation
        || coordinates.root_generation != original_coordinates.root_generation
        || coordinates.native_boundary_owner_id != original_coordinates.native_boundary_owner_id
        || coordinates.native_boundary_owner_epoch
            != original_coordinates.native_boundary_owner_epoch
        || coordinates.source_policy_version != original_coordinates.source_policy_version
        || coordinates.command_policy_version != original_coordinates.command_policy_version
        || coordinates.trust_record.instance_epoch
            != original_coordinates.trust_record.instance_epoch
        || coordinates.trust_record.status != original_coordinates.trust_record.status
        || coordinates.trust_record.managed_deny_mask
            != original_coordinates.trust_record.managed_deny_mask
        || current.selection.scope != current.scope.permission_scope
        || current.selection.scope != original.scope().permission_scope
        || current.selection.preset_version != PresetVersion::V1
        || current.scope.validate().is_err()
        || !same_nonmanaged_scope_shape(&current.scope, original.scope())
        || current.command != *original.command()
        || current.command_intent_digest != original.command_intent_digest()
        || current.limits != original.limits()
    {
        return Err(RetainedNotEvaluableReasonV1::OwnerCompatibilityRequired);
    }
    match &observation.boundary {
        RetainedBoundaryObservationV1::Unavailable(_) => {
            return Err(RetainedNotEvaluableReasonV1::OwnerCompatibilityRequired);
        }
        RetainedBoundaryObservationV1::Observed {
            source_policy_version,
            command_policy_version,
            protected_generation,
            root_generation,
        } if *source_policy_version != coordinates.source_policy_version
            || *command_policy_version != coordinates.command_policy_version
            || *protected_generation != coordinates.protected_generation
            || *root_generation != coordinates.root_generation =>
        {
            return Err(RetainedNotEvaluableReasonV1::OwnerCompatibilityRequired);
        }
        RetainedBoundaryObservationV1::Observed { .. } => {}
    }
    match current.execution_observation {
        RetainedExecutionObservationV1::Cancelled
        | RetainedExecutionObservationV1::Revoked
        | RetainedExecutionObservationV1::TerminalCommitted => {
            return Err(RetainedNotEvaluableReasonV1::ExecutionNotActive);
        }
        RetainedExecutionObservationV1::Unavailable => {
            return Err(RetainedNotEvaluableReasonV1::ExecutionUnavailable);
        }
        RetainedExecutionObservationV1::Active => {}
    }
    Ok(())
}
