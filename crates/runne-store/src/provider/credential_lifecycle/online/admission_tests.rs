use runne_provider::{
    ClaimCredentialOperation, CredentialFence, HardFenceProvider, ProviderCredentialEnrollmentStore,
};

use super::online_claim_test_support::{open_test_store, seal_claim};
use super::online_test_support::{
    begin, claim_at, complete_pair, digest, issue_ticket, operation, provider, store, ticket, ticket_at,
    ticket_state,
};

#[test]
fn begin_admission_snapshot_initializes_first_provider_head() {
    let store = store();

    let snapshot =
        ProviderCredentialEnrollmentStore::begin_admission_snapshot(&store, &provider()).unwrap();

    assert_eq!(snapshot.lifecycle_revision().get(), 1);
    assert_eq!(snapshot.fence().get(), 1);
    assert_eq!(snapshot.readiness_revision().get(), 1);
    assert_eq!(snapshot.next_credential_version(), 1);
    assert_eq!(snapshot.active_version(), None);
}

#[test]
fn stale_admission_snapshot_begin_conflicts_without_allocator_mutation() {
    let store = store();
    let snapshot =
        ProviderCredentialEnrollmentStore::begin_admission_snapshot(&store, &provider()).unwrap();
    ProviderCredentialEnrollmentStore::hard_fence_provider(
        &store,
        HardFenceProvider::new(
            provider(),
            snapshot.fence(),
            CredentialFence::new(2).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        ProviderCredentialEnrollmentStore::begin(&store, begin(101, "stale-admission", 102))
            .unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    let next: i64 = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT next_credential_version FROM provider_credential_authority_heads WHERE provider_id=?1",
            [provider().as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(next, 1);
}

#[test]
fn begin_admission_snapshot_hydrates_exact_active_ref() {
    let store = store();
    complete_pair(&store, 103, "active-admission");

    let snapshot =
        ProviderCredentialEnrollmentStore::begin_admission_snapshot(&store, &provider()).unwrap();

    assert_eq!(snapshot.active_version().unwrap().provider(), &provider());
    assert_eq!(snapshot.active_version().unwrap().version(), 1);
}

#[test]
fn begin_admission_snapshot_rejects_corrupted_active_digest() {
    let store = store();
    complete_pair(&store, 104, "corrupt-active-admission");
    let connection = store.connection.lock().unwrap();
    connection
        .execute_batch("DROP TRIGGER provider_credential_head_active_lifecycle")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_credential_authority_heads SET active_ref_digest=?1 WHERE provider_id=?2",
            rusqlite::params![[99_u8; 32], provider().as_str()],
        )
        .unwrap();
    drop(connection);

    assert_eq!(
        ProviderCredentialEnrollmentStore::begin_admission_snapshot(&store, &provider())
            .unwrap_err(),
        runne_provider::CredentialLifecycleError::CorruptState
    );
}

#[test]
fn credential_online_ticket_issue_rechecks_current_head() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(110, "ticket-head-cas", 111)).unwrap();
    ProviderCredentialEnrollmentStore::hard_fence_provider(
        &store,
        HardFenceProvider::new(
            provider(),
            CredentialFence::new(1).unwrap(),
            CredentialFence::new(2).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();

    let result =
        issue_ticket(&store, ticket(110, 1, 112, 113));

    assert_eq!(
        result.unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    let attempts = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM provider_credential_ticket_attempts WHERE operation_id=?1",
            [operation(110).as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(attempts, 0);
}

#[test]
fn credential_online_ticket_issue_uses_store_clock_not_caller_timestamps() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(120, "future-ticket", 121)).unwrap();
    let receipt = issue_ticket(
        &store,
        ticket_at(120, 1, 122, 123, 150, 200),
    )
    .unwrap();

    assert_eq!(receipt.issued_at_high_water(), 100);
    assert_eq!(receipt.expires_at_high_water(), 150);
}

#[test]
fn credential_online_expired_ticket_stays_closed_after_clock_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ticket-rollback.sqlite");
    let store = open_test_store(&path, 100);
    ProviderCredentialEnrollmentStore::begin(&store, begin(130, "expiry-rollback", 131)).unwrap();
    issue_ticket(
        &store,
        ticket_at(130, 1, 132, 133, 100, 200),
    )
    .unwrap();
    drop(store);

    let expired = open_test_store(&path, 201);
    assert_eq!(
        ProviderCredentialEnrollmentStore::claim(
            &expired,
            seal_claim(&expired, claim_at(&expired, 130, 1, 132, 133, 134)),
        )
        .unwrap_err(),
        runne_provider::CredentialLifecycleError::StaleLease
    );
    assert_eq!(ticket_state(&expired, 130, 1), "TOMBSTONED");
    drop(expired);

    let rolled_back = open_test_store(&path, 150);
    assert!(
        ProviderCredentialEnrollmentStore::claim(
            &rolled_back,
            seal_claim(&rolled_back, claim_at(&rolled_back, 130, 1, 132, 133, 134),),
        )
        .is_err()
    );
    assert_eq!(ticket_state(&rolled_back, 130, 1), "TOMBSTONED");
}

#[test]
fn credential_online_ticket_reissue_tombstones_and_allocates_store_next_attempt() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(140, "issue-high-water", 141)).unwrap();
    issue_ticket(
        &store,
        ticket_at(140, 1, 142, 143, 100, 200),
    )
    .unwrap();

    let receipt = issue_ticket(
        &store,
        ticket_at(140, 2, 144, 145, 90, 200),
    )
    .unwrap();

    assert_eq!(ticket_state(&store, 140, 1), "TOMBSTONED");
    assert_eq!(receipt.ticket_attempt().get(), 2);
    assert_eq!(receipt.issued_at_high_water(), 100);
}

#[test]
fn credential_online_unsealed_claim_cannot_consume_a_matching_ticket() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(150, "unsealed-claim", 151)).unwrap();
    issue_ticket(
        &store,
        ticket_at(150, 1, 152, 153, 100, 200),
    )
    .unwrap();

    let result =
        ProviderCredentialEnrollmentStore::claim(&store, claim_at(&store, 150, 1, 152, 153, 154));

    assert_eq!(
        result.unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    assert_eq!(ticket_state(&store, 150, 1), "ISSUED");
}

#[test]
fn credential_online_claim_rejects_substituted_receipt_owner_without_consuming_ticket() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(160, "owner-substitution", 161))
        .unwrap();
    let receipt = issue_ticket(&store, ticket(160, 1, 162, 163)).unwrap();
    let connection = store.connection.lock().unwrap();
    connection
        .execute_batch("DROP TRIGGER provider_credential_operation_transition")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_credential_operations SET installation_owner_id=?1 WHERE operation_id=?2",
            rusqlite::params![[43_u8; 32], operation(160).as_bytes().as_slice()],
        )
        .unwrap();
    drop(connection);

    let claim = seal_claim(
        &store,
        ClaimCredentialOperation::new(receipt, digest(162), digest(163), digest(164), 1, 1)
            .unwrap(),
    );

    assert_eq!(
        ProviderCredentialEnrollmentStore::claim(&store, claim).unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    assert_eq!(ticket_state(&store, 160, 1), "ISSUED");
}
