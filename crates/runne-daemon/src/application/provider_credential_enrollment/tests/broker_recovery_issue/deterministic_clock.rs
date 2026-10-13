use super::super::nested_db;
use runne_api::ProviderCredentialEnrollmentHostError;
use runne_store::provider::online_claim_test_support::{
    open_test_store_with_authorities, reopen_test_store_with_authority,
};

use super::*;

/// Deterministic clock boundaries for the broker recovery chain. The accepted
/// cleanup recovery anchors at the fixture store clock with the unchanged
/// TTL of 30 seconds; ticket issuance is exercised against the SAME paired
/// store seal reopened at an advanced verification clock, so the lease edge
/// is proven without any wall-clock dependence.
fn issue_on_reopened_store_at(
    f: &Fixture,
    clock: i64,
    accepted: AcceptedCredentialCleanupRecovery,
) -> Result<IssuedCredentialTicketAttempt, ProviderCredentialEnrollmentHostError> {
    let store = reopen_test_store_with_authority(
        &nested_db(f._directory.path(), "broker.sqlite"),
        f.enrollment_authority.clone(),
        clock,
    );
    let context = f
        .broker
        .claim_issue_context(
            recovery_measurements(f, [9; 32], [17; 32]),
            [21; 32],
            f.continuation,
            7,
            8,
        )
        .unwrap();
    let mut channel = RecordingChannel::default();
    f.broker
        .issue_ticket(accepted, f.continuation, &context, 60, &store, &mut channel)
}

#[test]
fn recovery_lease_issue_succeeds_before_the_ttl_edge() {
    let (f, accepted) = recovery_fixture();
    let receipt = issue_on_reopened_store_at(&f, FIXTURE_NOW_SECONDS + 29, accepted).unwrap();
    assert_eq!(receipt.ticket_attempt().get(), 1);
}

#[test]
fn recovery_lease_issue_is_refused_at_the_exact_ttl_edge() {
    let (f, accepted) = recovery_fixture();
    let error = issue_on_reopened_store_at(&f, FIXTURE_NOW_SECONDS + 30, accepted)
        .expect_err("store clock == lease expiry must already be refused");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::Conflict
    ));
}

#[test]
fn recovery_lease_issue_is_refused_past_the_ttl_edge() {
    let (f, accepted) = recovery_fixture();
    let error = issue_on_reopened_store_at(&f, FIXTURE_NOW_SECONDS + 31, accepted)
        .expect_err("store clock past the lease expiry must be refused");
    assert!(matches!(
        error,
        ProviderCredentialEnrollmentHostError::Conflict
    ));
}

#[test]
fn begin_high_water_expiry_edge_is_refused_at_the_deterministic_clock() {
    let directory = tempfile::tempdir().unwrap();
    let (store, _authority, measurements) = open_test_store_with_authorities(
        &nested_db(directory.path(), "begin-edge.sqlite"),
        FIXTURE_NOW_SECONDS + BEGIN_EXPIRY_MARGIN_SECONDS + 1,
    );
    let provider = ProviderId::new("openai").unwrap();
    let input = BeginCredentialOperation::new(
        CommandId::from_bytes([81; 16]),
        IdempotencyKey::new("begin-ttl-edge").unwrap(),
        CredentialOperationId::from_bytes([82; 16]).unwrap(),
        CredentialInstallationOwnerId::from_bytes([3; 32]).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(CredentialVersionRef::new(provider, 1).unwrap()),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        CredentialBindingDigest::from_measured([83; 32]).unwrap(),
        u64::try_from(FIXTURE_NOW_SECONDS + BEGIN_EXPIRY_MARGIN_SECONDS).unwrap(),
    )
    .unwrap()
    .with_qualified_release_tuple(
        measurements
            .issue_qualified_credential_release_tuple(
                measurements.release_manifest_digest([9; 32]).unwrap(),
            )
            .unwrap(),
    );
    assert!(matches!(
        store.begin(input),
        Err(runne_provider::CredentialLifecycleError::StaleLease)
    ));
}
