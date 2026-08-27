use runne_api::{
    ProviderCredentialEnrollmentHostError, ProviderCredentialProviderV2,
    ProviderCredentialRequestAuthorityPair,
};
use runne_provider::CredentialEnrollmentAuthorityPair;

use super::super::{ProviderCredentialAdmission, ProviderCredentialEnrollmentStatus};
use super::recovery::fixture::{FailurePoint, Fixture, StatefulReader};

#[test]
fn authorized_status_recovers_before_returning_the_safe_projection() {
    let fixture = Fixture::retired_cleanup(FailurePoint::None);
    let reader = StatefulReader::new(&fixture);
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let status = ProviderCredentialEnrollmentStatus::new(
        ProviderCredentialAdmission::new(verifier, measurements),
        &fixture,
        &reader,
    );
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();

    let projection = status
        .load(&authority, ProviderCredentialProviderV2::OpenAi, 100)
        .unwrap();

    assert_eq!(
        projection.provider_id(),
        ProviderCredentialProviderV2::OpenAi
    );
    assert_eq!(
        projection.credential_state(),
        runne_api::ProviderCredentialStateV2::Missing
    );
    assert_eq!(
        fixture.events(),
        [
            "reconcile",
            "mark",
            "readback",
            "bind",
            "complete",
            "safe_snapshot"
        ]
    );
}

#[test]
fn unauthorized_status_skips_recovery_and_store_access() {
    let fixture = Fixture::retired_cleanup(FailurePoint::None);
    let reader = StatefulReader::new(&fixture);
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let (_, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let status = ProviderCredentialEnrollmentStatus::new(
        ProviderCredentialAdmission::new(verifier, measurements),
        &fixture,
        &reader,
    );
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();

    assert_eq!(
        status.load(&authority, ProviderCredentialProviderV2::OpenAi, 100),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
    assert!(fixture.events().is_empty());
}
