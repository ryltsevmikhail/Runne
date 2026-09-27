use runne_application::provider::ProviderAdmissionError;
use runne_runtime::canonical_provider_execution::CanonicalProviderExecutionError;
use runne_store::provider::ProviderCoordinatorOutcome;

pub(super) fn record(stage: &'static str, succeeded: bool) {
    crate::protected_activation::linux_pair_diagnostics::record(stage, succeeded);
}

pub(super) const fn projection_failure_stage(
    error: CanonicalProviderExecutionError,
) -> &'static str {
    match error {
        CanonicalProviderExecutionError::Unavailable => "provider_projection_unavailable",
        CanonicalProviderExecutionError::Conflict => "provider_projection_conflict",
        _ => "provider_projection_other",
    }
}

pub(super) const fn admission_failure_stage(error: &ProviderAdmissionError) -> &'static str {
    match error {
        ProviderAdmissionError::RepositoryFailure => "provider_admission_repository",
        ProviderAdmissionError::PolicyDenied => "provider_admission_policy",
        ProviderAdmissionError::AuthorityDenied
        | ProviderAdmissionError::CapabilityDenied
        | ProviderAdmissionError::CapabilityExpired
        | ProviderAdmissionError::ApprovalDenied
        | ProviderAdmissionError::ApprovalExpired
        | ProviderAdmissionError::CapabilityRevoked
        | ProviderAdmissionError::ApprovalRevoked => "provider_admission_authority",
        ProviderAdmissionError::TokenBudgetDenied | ProviderAdmissionError::CostBudgetDenied => {
            "provider_admission_budget"
        }
        ProviderAdmissionError::PrepareRejected => "provider_admission_prepare",
        ProviderAdmissionError::AuthorityConflict
        | ProviderAdmissionError::PricingRevisionMismatch
        | ProviderAdmissionError::InvalidSemanticContext
        | ProviderAdmissionError::TokenReservationMismatch
        | ProviderAdmissionError::CostReservationMismatch
        | ProviderAdmissionError::RenderDigestMismatch
        | ProviderAdmissionError::PermitMismatch
        | ProviderAdmissionError::StaleFencingToken => "provider_admission_conflict",
        ProviderAdmissionError::PostClaimUncertain => "provider_admission_uncertain",
    }
}

pub(super) const fn outcome_stage(outcome: &ProviderCoordinatorOutcome) -> &'static str {
    match outcome {
        ProviderCoordinatorOutcome::Streaming { .. } => "provider_dispatch_streaming",
        ProviderCoordinatorOutcome::Existing { .. } => "provider_dispatch_existing",
        ProviderCoordinatorOutcome::RejectedBeforeEffect { .. } => "provider_dispatch_rejected",
        ProviderCoordinatorOutcome::Uncertain => "provider_dispatch_uncertain",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_and_policy_rejections_have_distinct_closed_codes() {
        assert_eq!(
            admission_failure_stage(&ProviderAdmissionError::RepositoryFailure),
            "provider_admission_repository"
        );
        assert_eq!(
            admission_failure_stage(&ProviderAdmissionError::PolicyDenied),
            "provider_admission_policy"
        );
        assert_eq!(
            projection_failure_stage(CanonicalProviderExecutionError::Unavailable),
            "provider_projection_unavailable"
        );
    }
}
