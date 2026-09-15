use runne_provider::{CredentialLifecycleError, ProviderCredentialEnrollmentStore};

use super::online_claim_test_support::{open_test_store, reopen_test_store};
use super::online_test_support::{
    begin_with_operation, issue_ticket, operation, ticket, ticket_state,
};

#[test]
fn credential_online_ticket_expiry_boundaries_gate_initial_issue() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("initial-expiry.sqlite");
    let valid = open_test_store(&path, 99);
    ProviderCredentialEnrollmentStore::begin(
        &valid,
        begin_with_operation(141, 141, "expiry-minus-one", 142, 100),
    )
    .unwrap();
    assert!(issue_ticket(&valid, ticket(141, 1, 143, 144),).is_ok());
    drop(valid);

    let equal = open_test_store(&path, 100);
    assert_stale_reissue(&equal, 141, 147, 148, 100);
    drop(equal);

    let after = open_test_store(&path, 101);
    assert_stale_reissue(&after, 141, 149, 150, 101);
}

#[test]
fn credential_online_two_connections_keep_expired_reissue_unchanged_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("expiry-reissue.sqlite");
    let first = open_test_store(&path, 99);
    ProviderCredentialEnrollmentStore::begin(
        &first,
        begin_with_operation(151, 151, "two-connections", 152, 100),
    )
    .unwrap();
    issue_ticket(&first, ticket(151, 1, 153, 154)).unwrap();
    let second = reopen_test_store(&path, 100);

    assert_stale_reissue(&second, 151, 155, 156, 100);
    drop(first);
    drop(second);

    let rolled_back = open_test_store(&path, 99);
    assert_stale_reissue(&rolled_back, 151, 157, 158, 100);
}

fn assert_stale_reissue(
    store: &super::SqliteProviderCredentialLifecycleStore,
    operation_value: u8,
    ticket_value: u8,
    continuation: u8,
    high_water: i64,
) {
    assert_eq!(
        issue_ticket(
            store,
            ticket(operation_value, 2, ticket_value, continuation),
        )
        .unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
    assert_eq!(ticket_state(store, operation_value, 1), "ISSUED");
    assert_eq!(ticket_attempt_count(store, operation_value), 1);
    assert_eq!(observed_at_high_water(store), high_water);
}

fn ticket_attempt_count(store: &super::SqliteProviderCredentialLifecycleStore, value: u8) -> i64 {
    store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM provider_credential_ticket_attempts WHERE operation_id=?1",
            [operation(value).as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

fn observed_at_high_water(store: &super::SqliteProviderCredentialLifecycleStore) -> i64 {
    store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT observed_at_high_water FROM provider_credential_authority_heads WHERE provider_id='openai'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}
