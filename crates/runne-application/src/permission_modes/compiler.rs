//! Deterministic V1 permission compiler. It grants no authority of its own.

use runne_domain::id::IntegrityDigest;

use super::retained::{RetainedPolicyEvaluationV1, RetainedPolicyInputV1};
use super::{
    binding::ApprovalBinding,
    composite::{CompositeEffectScope, CompositeScopeDigest, ContainmentStrategy},
    model::{ModeSelection, PermissionMode, PresetVersion},
    readiness::{EffectiveModeState, NativeScopeAdmissionReceipt},
    resource::{PermissionAction, ResourceFacts},
};

#[path = "compiler_closed_coverage.rs"]
pub(super) mod closed_coverage;
#[path = "compiler_evidence.rs"]
pub(super) mod evidence;

/// Runtime-owned managed-policy outcome for this exact invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedPolicyEvaluation {
    /// Canonical scope evaluated by the managed-policy owner.
    pub scope_digest: CompositeScopeDigest,
    /// Policy snapshot that produced `disposition`.
    pub policy_digest: IntegrityDigest,
    /// Matching result; deny and ask override every preset.
    pub disposition: ManagedDisposition,
}

/// Managed policy result for one action/resource tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedDisposition {
    Allow,
    Ask,
    Deny,
}

/// Exact operation, its host-derived facts, and any existing durable approval.
#[derive(Debug, Clone)]
pub struct InvocationPolicyRequest {
    /// Canonical action taxonomy entry.
    pub action: PermissionAction,
    /// Host-resolved resource facts; unknown values never auto-admit.
    pub resource: ResourceFacts,
    /// Exact scope requested by this one invocation.
    pub composite_scope: CompositeEffectScope,
    /// Candidate produced from the immutable invocation and exact target.
    pub candidate_binding: ApprovalBinding,
    /// Existing durable approval loaded by the authoritative runtime owner.
    pub approved_binding: Option<ApprovalBinding>,
    /// Exact-scope native receipt; absence means no effect can be released.
    pub native_admission: Option<NativeScopeAdmissionReceipt>,
}

/// Inputs from the existing selection, enforcement, managed-policy and invocation owners.
#[derive(Debug, Clone)]
pub struct PolicyEvaluationInput {
    /// Durable selection (missing rows use `ModeSelection::missing`).
    pub selection: ModeSelection,
    /// Scope for which the selected/effective mode was admitted.
    pub effective_scope: CompositeEffectScope,
    /// Honest native effective-mode state, independent of user selection.
    pub effective: EffectiveModeState,
    /// One exact invocation to compile.
    pub invocation: InvocationPolicyRequest,
    /// Exact managed-policy evaluation for that invocation.
    pub managed: ManagedPolicyEvaluation,
    /// Trusted runtime clock used for expiry.
    pub now_unix_ms: i64,
}

/// Why a matching approval cannot replace preset auto-admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalReason {
    ManagedAsk,
    AskAlways,
    RiskOrScopeUnknown,
}

/// Approval lifecycle unit; D2.1 approvals are invocation-scoped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalUnit {
    Invocation,
}

/// Stable fail-closed compiler result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Effect may proceed only with this exact native handle and binding.
    Allow {
        /// The selected preset that was actually admitted.
        effective_mode: PermissionMode,
        /// Exact native invocation admission retained by the executor.
        native_admission: NativeScopeAdmissionReceipt,
        /// Exact invocation scope used by native admission.
        composite_scope_digest: CompositeScopeDigest,
        /// Approval compatibility key for audit and effect release.
        approval_binding_digest: IntegrityDigest,
    },
    /// Durable exact invocation approval is required before effect release.
    RequireApproval {
        /// Why this preset requested confirmation.
        reason: ApprovalReason,
        /// Canonical approval lifecycle granularity.
        unit: ApprovalUnit,
        /// Binding that must be approved and revalidated at release.
        approval_binding_digest: IntegrityDigest,
    },
    /// Stable refusal; no caller-provided accepted state can override it.
    Deny(DenyReason),
}

/// Stable V1 refusal vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// A matching managed rule denied the exact invocation.
    ManagedPolicy,
    /// Selected mode does not have an admitted native effective state.
    EffectiveModeNotReady,
    /// Scope, receipt, managed evaluation, or immutable binding disagrees.
    ScopeOrEvidenceMismatch,
    /// The chosen preset version is not implemented here.
    UnsupportedPreset,
    /// The requested mode or exact approval has expired.
    Expired,
    /// The requested effect is outside the admitted scope or cannot be enforced.
    OutsideAdmittedScope,
}

/// Deterministic typed policy compiler; no state is stored or mutated here.
pub struct PermissionPolicyCompiler;

impl PermissionPolicyCompiler {
    /// Observe retained policy compatibility without producing effect authority.
    pub fn evaluate_retained_v1(input: &RetainedPolicyInputV1<'_>) -> RetainedPolicyEvaluationV1 {
        super::retained::evaluate_retained_v1(input)
    }

    /// Compile one request to allow, exact approval, or stable deny.
    pub fn compile(input: &PolicyEvaluationInput) -> PolicyDecision {
        if input.invocation.composite_scope.containment == ContainmentStrategy::SameUserCompositeV2
        {
            evidence::compile(input)
        } else {
            closed_coverage::compile_legacy(input)
        }
    }
}

pub(super) fn allow(
    mode: PermissionMode,
    native_admission: NativeScopeAdmissionReceipt,
    composite_scope_digest: CompositeScopeDigest,
    approval_binding_digest: IntegrityDigest,
) -> PolicyDecision {
    PolicyDecision::Allow {
        effective_mode: mode,
        native_admission,
        composite_scope_digest,
        approval_binding_digest,
    }
}
