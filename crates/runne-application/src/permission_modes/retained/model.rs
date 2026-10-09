//! Data-only inputs and outputs for retained permission-policy evaluation.

use runne_api::ApiPrincipalId;
use runne_domain::id::{IntegrityDigest, InvocationId, ProjectId, WorkspaceId};

use crate::{ports::TaskRunAssignmentIdentity, project_trust::ProjectTrustRecord};

use super::{
    approval::RetainedHumanEvidenceV1,
    current_facts::{RetainedExecutionObservationV1, RetainedObservationContextV1},
    semantics::RetainedRelevantSemanticsV1,
};
use crate::{
    permission_modes::{
        binding::ApprovalBinding,
        composite::{CompositeEffectScope, CompositeScopeDigest},
        local_command_binding::LocalCommandPermissionBindingV1,
        local_command_limits::LocalInvocationLimitsV1,
        model::ModeSelection,
        resource::PermissionAction,
    },
    project_trust::ProjectTrustEffectPolicySnapshot,
};

/// Version of the pure retained evaluator. It does not change legacy encoders.
pub const RETAINED_POLICY_EVALUATOR_VERSION_V1: u16 = 1;
/// Version of the retained relevant-semantics projection.
pub const RETAINED_RELEVANT_SEMANTICS_VERSION_V1: u16 = 1;
/// Source-owner capture format required by the first retained evaluator.
pub const RETAINED_SOURCE_CAPTURE_VERSION_V1: u16 = 1;

/// Independently observed identity and owner coordinates for one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedOwnerCoordinatesV1 {
    pub runtime_authority_id: String,
    pub principal_id: ApiPrincipalId,
    pub workspace_id: WorkspaceId,
    pub project_id: ProjectId,
    pub project_version: u64,
    pub workspace_version: u64,
    pub admitted_root_version: u64,
    pub held_root_identity_digest: IntegrityDigest,
    pub assignment: TaskRunAssignmentIdentity,
    pub claim_stream_version: u64,
    pub invocation_id: InvocationId,
    pub root_generation: u64,
    pub protected_generation: u64,
    pub native_boundary_owner_id: String,
    pub native_boundary_owner_epoch: u64,
    pub protected_policy_digest: IntegrityDigest,
    pub source_policy_version: u64,
    pub command_policy_version: u64,
    pub trust_record: ProjectTrustRecord,
}

/// Clock values are observations in milliseconds within an opaque epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetainedClockObservationV1 {
    pub epoch: u64,
    pub wall_unix_ms: i64,
    pub monotonic_ms: u64,
}

/// Caller-supplied original-owner capture. This is checked data, not attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedOriginalContextInputV1 {
    pub original_binding_digest: IntegrityDigest,
    pub capture_format_version: u16,
    pub source_record_version: u16,
    pub coordinates: RetainedOwnerCoordinatesV1,
    pub admission_clock: RetainedClockObservationV1,
    pub selection_expiry_unix_ms: Option<i64>,
    pub invocation_deadline_unix_ms: i64,
}

/// Immutable, internally correlated original-owner data; never an authority token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedOriginalContextV1 {
    pub(super) original_binding_digest: IntegrityDigest,
    pub(super) capture_format_version: u16,
    pub(super) source_record_version: u16,
    pub(super) coordinates: RetainedOwnerCoordinatesV1,
    pub(super) admission_clock: RetainedClockObservationV1,
    pub(super) selection_expiry_unix_ms: Option<i64>,
    pub(super) invocation_deadline_unix_ms: i64,
}

/// Current facts supplied independently by permission, trust, root and clock owners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedCurrentFactsInputV1 {
    pub original_binding_digest: IntegrityDigest,
    pub selection: ModeSelection,
    pub scope: CompositeEffectScope,
    pub project_id: ProjectId,
    pub snapshot: ProjectTrustEffectPolicySnapshot,
    pub app_policy_digest: IntegrityDigest,
    pub command: runne_domain::task_run::TaskRunLocalCommand,
    pub command_intent_digest: IntegrityDigest,
    pub limits: LocalInvocationLimitsV1,
    pub candidate: ApprovalBinding,
    pub coordinates: RetainedOwnerCoordinatesV1,
    pub observed_clock: RetainedClockObservationV1,
    pub observation_context: Option<RetainedObservationContextV1>,
    pub execution_observation: RetainedExecutionObservationV1,
    pub assignment_lease_deadline_unix_ms: i64,
}

/// Checked current snapshot data; a constructor does not prove its owner provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedCurrentFactsV1 {
    pub(super) original_binding_digest: IntegrityDigest,
    pub(super) selection: ModeSelection,
    pub(super) scope: CompositeEffectScope,
    pub(super) project_id: ProjectId,
    pub(super) snapshot: ProjectTrustEffectPolicySnapshot,
    pub(super) app_policy_digest: IntegrityDigest,
    pub(super) command: runne_domain::task_run::TaskRunLocalCommand,
    pub(super) command_intent_digest: IntegrityDigest,
    pub(super) limits: LocalInvocationLimitsV1,
    pub(super) candidate: ApprovalBinding,
    pub(super) coordinates: RetainedOwnerCoordinatesV1,
    pub(super) observed_clock: RetainedClockObservationV1,
    pub(super) observation_context: Option<RetainedObservationContextV1>,
    pub(super) execution_observation: RetainedExecutionObservationV1,
    pub(super) assignment_lease_deadline_unix_ms: i64,
}

/// Runtime phase. The associated observations are separately supplied below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedPhaseV1 {
    BeforeGo,
    Running,
    Terminal,
}

/// Separately observed start clock and elapsed runtime for Running/Terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetainedRuntimeStartV1 {
    pub original_binding_digest: IntegrityDigest,
    pub invocation_id: InvocationId,
    pub clock_epoch: u64,
    pub monotonic_start_ms: u64,
    pub wall_start_unix_ms: i64,
}

/// Phase observations; BeforeGo must omit both runtime fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetainedPhaseObservationV1 {
    pub phase: RetainedPhaseV1,
    pub runtime_start: Option<RetainedRuntimeStartV1>,
    pub elapsed_runtime_ms: Option<u64>,
}

/// Original admission is explicit: Auto never stands in for Human evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedAdmissionEvidenceV1<'a> {
    Pending,
    Auto,
    Human(&'a RetainedHumanEvidenceV1),
}

/// Exact original identity candidate plus independently retained observations.
#[derive(Debug, Clone, Copy)]
pub struct RetainedPolicyInputV1<'a> {
    pub original: &'a LocalCommandPermissionBindingV1,
    pub original_context: Option<&'a RetainedOriginalContextV1>,
    pub current: &'a RetainedCurrentFactsV1,
    pub original_identity_candidate: &'a ApprovalBinding,
    pub admission: RetainedAdmissionEvidenceV1<'a>,
    pub selected_human_candidate: Option<&'a RetainedHumanEvidenceV1>,
    pub phase: RetainedPhaseObservationV1,
    pub action: PermissionAction,
    pub resource: &'a super::super::resource::ResourceFacts,
}

/// Stable data-consistency failures; none imply a policy grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedNotEvaluableReasonV1 {
    MissingOriginalContext,
    MissingAdmission,
    MissingCurrentObservation,
    OwnerCompatibilityRequired,
    OriginalContextInconsistent,
    CurrentFactsInconsistent,
    OriginalIdentityMismatch,
    UnsupportedVersion,
    UnsupportedScope,
    ApprovalEvidenceInconsistent,
    ClockObservationInconsistent,
    PhaseObservationInconsistent,
    ExecutionNotActive,
    ExecutionUnavailable,
    AssignmentLeaseExpired,
    OriginalGrantExpired,
}

/// Explicit approval requirement before GO or stop after GO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedApprovalRequirementV1 {
    ExactHumanApproval,
    StopRequired,
}

/// Each release boundary stays unresolved even for PolicyCompatible data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedReleaseRequirementStateV1 {
    Unresolved,
}

/// Fixed release blockers carried by every compatible policy observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetainedReleaseRequirementsV1 {
    pub owner_compatibility: RetainedReleaseRequirementStateV1,
    pub durable_admission_and_approval: RetainedReleaseRequirementStateV1,
    pub live_clock_and_lease: RetainedReleaseRequirementStateV1,
    pub native_one_go_lineage: RetainedReleaseRequirementStateV1,
    pub revoke_and_terminal_ordering: RetainedReleaseRequirementStateV1,
}

impl RetainedReleaseRequirementsV1 {
    pub(super) const fn unresolved() -> Self {
        Self {
            owner_compatibility: RetainedReleaseRequirementStateV1::Unresolved,
            durable_admission_and_approval: RetainedReleaseRequirementStateV1::Unresolved,
            live_clock_and_lease: RetainedReleaseRequirementStateV1::Unresolved,
            native_one_go_lineage: RetainedReleaseRequirementStateV1::Unresolved,
            revoke_and_terminal_ordering: RetainedReleaseRequirementStateV1::Unresolved,
        }
    }
}

/// Pure policy observation. No variant carries an effect permit or callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainedPolicyEvaluationV1 {
    PolicyCompatible {
        current_semantics: RetainedRelevantSemanticsV1,
        original_binding_digest: IntegrityDigest,
        current_scope_digest: CompositeScopeDigest,
        release_requirements: RetainedReleaseRequirementsV1,
    },
    RequireApproval {
        requirement: RetainedApprovalRequirementV1,
        original_binding_digest: IntegrityDigest,
        current_semantics_digest: IntegrityDigest,
    },
    StopRequired {
        requirement: RetainedApprovalRequirementV1,
        original_binding_digest: IntegrityDigest,
        current_semantics_digest: IntegrityDigest,
    },
    Denied,
    NotEvaluable(RetainedNotEvaluableReasonV1),
}
