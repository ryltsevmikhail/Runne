//! Pure retained permission compatibility; it never releases an effect.

mod approval;
mod bounds;
mod current_facts;
mod evaluate;
mod human_compatibility;
mod identity;
mod model;
mod phase;
mod provided_classes;
mod scope_compatibility;
mod semantics;
pub use scope_compatibility::*;
#[cfg(test)]
mod scope_compatibility_tests;

pub use approval::{RetainedHumanEvidenceInputV1, RetainedHumanEvidenceV1};
pub use current_facts::{
    RetainedBoundaryObservationV1, RetainedBoundaryUnavailableReasonV1,
    RetainedExecutionObservationV1, RetainedObservationContextV1,
};
pub use model::{
    RETAINED_POLICY_EVALUATOR_VERSION_V1, RETAINED_RELEVANT_SEMANTICS_VERSION_V1,
    RETAINED_SOURCE_CAPTURE_VERSION_V1, RetainedAdmissionEvidenceV1, RetainedApprovalRequirementV1,
    RetainedClockObservationV1, RetainedCurrentFactsInputV1, RetainedCurrentFactsV1,
    RetainedNotEvaluableReasonV1, RetainedOriginalContextInputV1, RetainedOriginalContextV1,
    RetainedOwnerCoordinatesV1, RetainedPhaseObservationV1, RetainedPhaseV1,
    RetainedPolicyEvaluationV1, RetainedPolicyInputV1, RetainedReleaseRequirementStateV1,
    RetainedReleaseRequirementsV1, RetainedRuntimeStartV1,
};
pub use semantics::RetainedRelevantSemanticsV1;

pub(super) fn evaluate_retained_v1(
    input: &RetainedPolicyInputV1<'_>,
) -> RetainedPolicyEvaluationV1 {
    evaluate::evaluate(input)
}

#[cfg(test)]
mod approval_tests;
#[cfg(test)]
mod bounds_tests;
#[cfg(test)]
mod compatibility_tests;
#[cfg(test)]
mod phase_tests;
#[cfg(test)]
mod tests_support;
