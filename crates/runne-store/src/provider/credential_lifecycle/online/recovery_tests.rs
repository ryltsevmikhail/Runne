use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    BeginCredentialOperation, ClosePreparedCredentialOperation, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationState,
    CredentialVersionRef, ProviderCredentialEnrollmentStore, ProviderId,
};

use super::online_claim_test_support::{open_test_store, seal_claim};
use super::online_test_support::{
    admit_claim, begin, claim_at, digest, issue_ticket, operation, qualified_release, store, ticket_at,
    ticket_state,
};

#[test]
fn credential_online_recovery_does_not_advance_unrelated_provider_clock() {
    let store = store();
    admit_claim(&store, 80, "recover-openai");
    let unrelated = ProviderId::new("anthropic").unwrap();
    ProviderCredentialEnrollmentStore::begin(&store, unrelated_begin(unrelated.clone())).unwrap();
    ProviderCredentialEnrollmentStore::cancel_before_claim(
        &store,
        ClosePreparedCredentialOperation::new(operation(81), CredentialOperationState::Cancelled)
            .unwrap(),
    )
    .unwrap();

    let work = ProviderCredentialEnrollmentStore::reconcile_online(&store, 500).unwrap();

    assert_eq!(work.len(), 1);
    assert_eq!(work[0].operation().operation_id(), operation(80));
    assert_eq!(observed_at(&store, &unrelated), 100);
}

#[test]
fn credential_online_recovery_tombstones_expired_prepared_ticket_before_clock_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("recovery-expiry.sqlite");
    let store = open_test_store(&path, 100);
    ProviderCredentialEnrollmentStore::begin(&store, begin(82, "recover-expired-ticket", 83))
        .unwrap();
    issue_ticket(
        &store,
        ticket_at(82, 1, 84, 85, 100, 200),
    )
    .unwrap();

    assert!(
        ProviderCredentialEnrollmentStore::reconcile_online(&store, 201)
            .unwrap()
            .is_empty()
    );
    assert_eq!(ticket_state(&store, 82, 1), "TOMBSTONED");
    drop(store);

    let rolled_back = open_test_store(&path, 150);
    assert_eq!(
        ProviderCredentialEnrollmentStore::claim(
            &rolled_back,
            seal_claim(&rolled_back, claim_at(&rolled_back, 82, 1, 84, 85, 86),),
        )
        .unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    assert_eq!(ticket_state(&rolled_back, 82, 1), "TOMBSTONED");
}

fn unrelated_begin(provider: ProviderId) -> BeginCredentialOperation {
    BeginCredentialOperation::new(
        CommandId::from_bytes([101; 16]),
        IdempotencyKey::new("closed-anthropic").unwrap(),
        operation(81),
        runne_provider::CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(CredentialVersionRef::new(provider, 1).unwrap()),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(102),
        200,
    )
    .unwrap()
    .with_qualified_release_tuple(qualified_release(92))
}

fn observed_at(
    store: &super::SqliteProviderCredentialLifecycleStore,
    provider: &ProviderId,
) -> i64 {
    store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT observed_at_high_water FROM provider_credential_authority_heads WHERE provider_id=?1",
            [provider.as_str()],
            |row| row.get(0),
        )
        .unwrap()
}
