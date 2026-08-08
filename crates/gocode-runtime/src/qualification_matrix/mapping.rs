//! Conservative, lossy projections from existing typed errors to the pure model.

use gocode_api::protected_activation::LaunchAuthorityError as AuthorityError;
use gocode_provider::CanonicalProviderError;

use super::QualificationRejection;

/// Projects every protected-activation error to a fail-closed rejection.
#[must_use]
pub fn rejection_from_launch_authority_error(error: &AuthorityError) -> QualificationRejection {
    match error {
        AuthorityError::ProfileHashMismatch
        | AuthorityError::ProviderProfileMismatch
        | AuthorityError::InvalidContract => QualificationRejection::ProfileDigestMismatch,
        AuthorityError::DowngradedExternalProfile
        | AuthorityError::ReadinessProofMismatch
        | AuthorityError::ReadinessTimeout
        | AuthorityError::ProtectedChannelUnavailable
        | AuthorityError::UnsupportedPlatformBackend => QualificationRejection::ProtectedV2Required,
        AuthorityError::ProviderModeMismatch => QualificationRejection::ModeMismatch,
        AuthorityError::OwnershipMismatch | AuthorityError::ExecutableIdentityMismatch => {
            QualificationRejection::OwnershipNotProven
        }
        AuthorityError::InstanceGenerationSessionMismatch
        | AuthorityError::MissingLaunchAuthority
        | AuthorityError::StaleLaunchAuthority
        | AuthorityError::ReusedLaunchAuthority
        | AuthorityError::RenewalReplay
        | AuthorityError::RenewalUnavailable => QualificationRejection::GenerationMismatch,
        AuthorityError::MissingExpectedStableBinding
        | AuthorityError::UnexpectedExistingEventLog
        | AuthorityError::FirstActivationPreparationMismatch
        | AuthorityError::FirstActivationCommitIncomplete => {
            QualificationRejection::LineageMismatch
        }
        AuthorityError::MissingProviderBinding => QualificationRejection::BlockedCredentials,
    }
}

/// Projects every canonical-provider error to a fail-closed rejection.
#[must_use]
pub fn rejection_from_canonical_provider_error(
    error: &CanonicalProviderError,
) -> QualificationRejection {
    match error {
        CanonicalProviderError::Serialization(_) | CanonicalProviderError::V1TextInputs => {
            QualificationRejection::ContractVersionDeniedForRole
        }
    }
}
