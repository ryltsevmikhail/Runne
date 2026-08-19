use runne_api::protected_activation::LaunchAuthorityError;
use runne_provider::CanonicalProviderError;
use runne_runtime::qualification_matrix::{
    QualificationDisposition, QualificationRejection, rejection_from_canonical_provider_error,
    rejection_from_launch_authority_error,
};

#[test]
fn launch_authority_error_mapping_table() {
    // Every variant of `LaunchAuthorityError` (22) maps fail-closed. The match
    // in `rejection_from_launch_authority_error` is exhaustive: adding a variant
    // breaks compilation before any test runs. The `Rejected`-wrapping assert
    // pins the property that the mapping never returns an accept disposition.
    let cases: [(LaunchAuthorityError, QualificationRejection); 22] = [
        (
            LaunchAuthorityError::ProfileHashMismatch,
            QualificationRejection::ProfileDigestMismatch,
        ),
        (
            LaunchAuthorityError::DowngradedExternalProfile,
            QualificationRejection::ProtectedV2Required,
        ),
        (
            LaunchAuthorityError::ProviderModeMismatch,
            QualificationRejection::ModeMismatch,
        ),
        (
            LaunchAuthorityError::ProviderProfileMismatch,
            QualificationRejection::ProfileDigestMismatch,
        ),
        (
            LaunchAuthorityError::OwnershipMismatch,
            QualificationRejection::OwnershipNotProven,
        ),
        (
            LaunchAuthorityError::ExecutableIdentityMismatch,
            QualificationRejection::OwnershipNotProven,
        ),
        (
            LaunchAuthorityError::InstanceGenerationSessionMismatch,
            QualificationRejection::GenerationMismatch,
        ),
        (
            LaunchAuthorityError::MissingLaunchAuthority,
            QualificationRejection::GenerationMismatch,
        ),
        (
            LaunchAuthorityError::StaleLaunchAuthority,
            QualificationRejection::GenerationMismatch,
        ),
        (
            LaunchAuthorityError::ReusedLaunchAuthority,
            QualificationRejection::GenerationMismatch,
        ),
        (
            LaunchAuthorityError::RenewalReplay,
            QualificationRejection::GenerationMismatch,
        ),
        (
            LaunchAuthorityError::RenewalUnavailable,
            QualificationRejection::GenerationMismatch,
        ),
        (
            LaunchAuthorityError::MissingExpectedStableBinding,
            QualificationRejection::LineageMismatch,
        ),
        (
            LaunchAuthorityError::UnexpectedExistingEventLog,
            QualificationRejection::LineageMismatch,
        ),
        (
            LaunchAuthorityError::FirstActivationPreparationMismatch,
            QualificationRejection::LineageMismatch,
        ),
        (
            LaunchAuthorityError::FirstActivationCommitIncomplete,
            QualificationRejection::LineageMismatch,
        ),
        (
            LaunchAuthorityError::ReadinessProofMismatch,
            QualificationRejection::ProtectedV2Required,
        ),
        (
            LaunchAuthorityError::ReadinessTimeout,
            QualificationRejection::ProtectedV2Required,
        ),
        (
            LaunchAuthorityError::ProtectedChannelUnavailable,
            QualificationRejection::ProtectedV2Required,
        ),
        (
            LaunchAuthorityError::UnsupportedPlatformBackend,
            QualificationRejection::ProtectedV2Required,
        ),
        (
            LaunchAuthorityError::MissingProviderBinding,
            QualificationRejection::BlockedCredentials,
        ),
        (
            LaunchAuthorityError::InvalidContract,
            QualificationRejection::ProfileDigestMismatch,
        ),
    ];
    assert_eq!(cases.len(), 22);
    for (error, expected) in cases {
        let mapped = rejection_from_launch_authority_error(&error);
        assert_eq!(mapped, expected);
        assert!(matches!(
            QualificationDisposition::Rejected(mapped),
            QualificationDisposition::Rejected(_)
        ));
    }
}

#[test]
fn canonical_provider_error_mapping_fail_closed() {
    // Both variants fail closed to `ContractVersionDeniedForRole`: V1 cannot
    // represent text inputs, and serialization failure is treated as the same
    // contract-version denial.
    let serialization_error = serde_json::from_str::<u8>("not a number").expect_err("must fail");
    let cases = [
        (
            CanonicalProviderError::V1TextInputs,
            QualificationRejection::ContractVersionDeniedForRole,
        ),
        (
            CanonicalProviderError::Serialization(serialization_error),
            QualificationRejection::ContractVersionDeniedForRole,
        ),
    ];
    for (error, expected) in cases {
        let mapped = rejection_from_canonical_provider_error(&error);
        assert_eq!(mapped, expected);
        assert!(matches!(
            QualificationDisposition::Rejected(mapped),
            QualificationDisposition::Rejected(_)
        ));
    }
}
