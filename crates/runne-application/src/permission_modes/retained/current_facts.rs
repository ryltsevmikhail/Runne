//! Bounded consistency checks for independently observed current data.

use runne_domain::id::IntegrityDigest;

use crate::project_trust::{ProjectTrustProjectId, managed_effect_policy_digest_v2};

use super::super::local_command_binding::LocalCommandPermissionBindingV1;
use super::model::{
    RetainedCurrentFactsInputV1, RetainedCurrentFactsV1, RetainedNotEvaluableReasonV1,
    RetainedOriginalContextInputV1, RetainedOriginalContextV1,
};
use super::{bounds, identity};

/// Why an independently queried owner boundary could not be observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedBoundaryUnavailableReasonV1 {
    MissingOwner,
    UnsupportedOwner,
    SnapshotUnavailable,
}

/// Provenance coordinates are observations only; this does not attest an owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainedBoundaryObservationV1 {
    Unavailable(RetainedBoundaryUnavailableReasonV1),
    Observed {
        source_policy_version: u64,
        command_policy_version: u64,
        protected_generation: u64,
        root_generation: u64,
    },
}

/// Correlated current observation context; it cannot establish live authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedObservationContextV1 {
    pub format_version: u16,
    pub original_binding_digest: IntegrityDigest,
    pub authorization_revision: u64,
    pub current_snapshot_digest: IntegrityDigest,
    pub native_boundary_owner_id: String,
    pub native_boundary_owner_epoch: u64,
    pub boundary: RetainedBoundaryObservationV1,
}

/// Persisted execution-state observation, subject to owner reload under fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedExecutionObservationV1 {
    Active,
    Cancelled,
    Revoked,
    TerminalCommitted,
    Unavailable,
}

impl RetainedOriginalContextV1 {
    /// Checks an immutable original capture against the checked portable binding.
    /// This verifies DATA consistency, not the identity or authority of a capturer.
    pub fn checked(
        original: &LocalCommandPermissionBindingV1,
        input: RetainedOriginalContextInputV1,
    ) -> Result<Self, RetainedNotEvaluableReasonV1> {
        if !bounds::original_within_bounds(original)
            || !bounds::coordinates_within_bounds(&input.coordinates)
            || !identity::coordinates_well_formed(&input.coordinates)
            || !identity::clock_well_formed(input.admission_clock)
        {
            return Err(RetainedNotEvaluableReasonV1::OriginalContextInconsistent);
        }
        let coordinates = &input.coordinates;
        let scope = original.scope();
        let approval = original.approval();
        let expected_binding_digest = original.digest();
        if input.original_binding_digest != expected_binding_digest
            || input.capture_format_version != super::model::RETAINED_SOURCE_CAPTURE_VERSION_V1
            || input.source_record_version != super::model::RETAINED_SOURCE_CAPTURE_VERSION_V1
            || original.closed_rules_encoder_version() != 2
            || !identity::coordinates_well_formed(coordinates)
            || !identity::clock_well_formed(input.admission_clock)
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
            || coordinates.trust_record != original.closed_rules_snapshot().record
            || coordinates.source_policy_version != crate::project_trust::FROZEN_POLICY_VERSION
            || coordinates.command_policy_version
                != crate::project_trust::LOCAL_COMMAND_POLICY_VERSION
            || input.selection_expiry_unix_ms != original.selection().expires_at_unix_ms
            || input.invocation_deadline_unix_ms != approval.expires_at_unix_ms
            || input.invocation_deadline_unix_ms <= input.admission_clock.wall_unix_ms
            || input
                .selection_expiry_unix_ms
                .is_some_and(|expiry| expiry <= input.admission_clock.wall_unix_ms)
            || approval.relevant_policy_digest != scope.managed_policy.policy_digest()
        {
            return Err(RetainedNotEvaluableReasonV1::OriginalContextInconsistent);
        }
        Ok(Self {
            original_binding_digest: expected_binding_digest,
            capture_format_version: input.capture_format_version,
            source_record_version: input.source_record_version,
            coordinates: input.coordinates,
            admission_clock: input.admission_clock,
            selection_expiry_unix_ms: input.selection_expiry_unix_ms,
            invocation_deadline_unix_ms: input.invocation_deadline_unix_ms,
        })
    }
}

impl RetainedCurrentFactsV1 {
    /// Checks duplicated identities and canonical snapshot digests only.
    /// The caller remains responsible for owner provenance and liveness.
    pub fn checked(
        input: RetainedCurrentFactsInputV1,
    ) -> Result<Self, RetainedNotEvaluableReasonV1> {
        if !bounds::current_input_within_bounds(&input) {
            return Err(RetainedNotEvaluableReasonV1::CurrentFactsInconsistent);
        }
        let current = Self {
            original_binding_digest: input.original_binding_digest,
            selection: input.selection,
            scope: input.scope,
            project_id: input.project_id,
            snapshot: input.snapshot,
            app_policy_digest: input.app_policy_digest,
            command: input.command,
            command_intent_digest: input.command_intent_digest,
            limits: input.limits,
            candidate: input.candidate,
            coordinates: input.coordinates,
            observed_clock: input.observed_clock,
            observation_context: input.observation_context,
            execution_observation: input.execution_observation,
            assignment_lease_deadline_unix_ms: input.assignment_lease_deadline_unix_ms,
        };
        validate_current_structure(&current)?;
        Ok(current)
    }
}

pub(super) fn validate_current_structure(
    current: &RetainedCurrentFactsV1,
) -> Result<(), RetainedNotEvaluableReasonV1> {
    if !bounds::current_facts_within_bounds(current) {
        return Err(RetainedNotEvaluableReasonV1::CurrentFactsInconsistent);
    }
    let trust_project = ProjectTrustProjectId::from_bytes(*current.project_id.as_bytes());
    let app_digest = managed_effect_policy_digest_v2(trust_project, &current.snapshot)
        .map(IntegrityDigest::from_bytes)
        .ok_or(RetainedNotEvaluableReasonV1::CurrentFactsInconsistent)?;
    let closed = super::super::composite::ManagedPolicyCoverage::from_closed_snapshot(
        trust_project,
        &current.snapshot,
    )
    .ok_or(RetainedNotEvaluableReasonV1::CurrentFactsInconsistent)?;
    let coordinates = &current.coordinates;
    let scope = &current.scope;
    if !current.snapshot.is_valid()
        || app_digest != current.app_policy_digest
        || IntegrityDigest::from_bytes(current.command.intent_digest())
            != current.command_intent_digest
        || current.limits.admitted_invocations() != 1
        || current.limits.stdout_capture_bytes()
            > super::super::local_command_limits::MAX_LOCAL_COMMAND_CAPTURE_BYTES as u64
        || current.limits.stderr_capture_bytes()
            > super::super::local_command_limits::MAX_LOCAL_COMMAND_CAPTURE_BYTES as u64
        || current.limits.max_runtime().is_err()
        || current.candidate.action != crate::permission_modes::PermissionAction::ProcessStart
        || current.candidate.principal_id != coordinates.principal_id
        || current.candidate.invocation.task_run_id != coordinates.assignment.taskrun_id
        || current.candidate.invocation.attempt_id != coordinates.assignment.attempt_id
        || current.candidate.invocation.invocation_id != coordinates.invocation_id
        || current.candidate.containment_version != scope.containment
        || closed != scope.managed_policy
        || scope.validate().is_err()
        || !identity::coordinates_well_formed(coordinates)
        || !identity::clock_well_formed(current.observed_clock)
        || current
            .original_binding_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || coordinates.runtime_authority_id != scope.permission_scope.runtime_authority_id.0
        || coordinates.principal_id != scope.permission_scope.principal_id
        || coordinates.workspace_id != scope.permission_scope.workspace_id
        || coordinates.project_id != current.project_id
        || coordinates.protected_policy_digest != scope.protected_control_plane_policy_digest
        || coordinates.trust_record != current.snapshot.record
        || current.assignment_lease_deadline_unix_ms <= 0
        || current
            .observation_context
            .as_ref()
            .is_some_and(|observation| {
                observation.original_binding_digest != current.original_binding_digest
                    || observation.authorization_revision
                        != current.selection.authorization_revision
                    || observation.current_snapshot_digest != app_digest
            })
        || current.selection.scope != scope.permission_scope
        || current.selection.preset_version != super::super::model::PresetVersion::V1
        || current
            .selection
            .expires_at_unix_ms
            .is_some_and(|expiry| expiry <= 0)
    {
        return Err(RetainedNotEvaluableReasonV1::CurrentFactsInconsistent);
    }
    if current
        .observation_context
        .as_ref()
        .is_some_and(|observation| {
            observation.native_boundary_owner_id != coordinates.native_boundary_owner_id
                || observation.native_boundary_owner_epoch
                    != coordinates.native_boundary_owner_epoch
                || matches!(
                    &observation.boundary,
                    RetainedBoundaryObservationV1::Observed {
                        source_policy_version,
                        command_policy_version,
                        protected_generation,
                        root_generation,
                    } if *source_policy_version != coordinates.source_policy_version
                        || *command_policy_version != coordinates.command_policy_version
                        || *protected_generation != coordinates.protected_generation
                        || *root_generation != coordinates.root_generation
                )
        })
    {
        return Err(RetainedNotEvaluableReasonV1::OwnerCompatibilityRequired);
    }
    scope
        .digest()
        .map_err(|_| RetainedNotEvaluableReasonV1::CurrentFactsInconsistent)?;
    Ok(())
}
