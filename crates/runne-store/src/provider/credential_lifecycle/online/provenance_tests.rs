use runne_provider::{
    ClaimCredentialOperation, CredentialTicketAttempt, ProviderCredentialEnrollmentStore,
};

use super::online_claim_test_support::{open_test_store, seal_claim};
use super::online_test_support::{begin, digest, operation, ticket, ticket_state};

#[test]
fn credential_online_foreign_receipt_is_denied_without_consuming_ticket() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreign-receipt.sqlite");
    let local = open_test_store(&path, 100);
    ProviderCredentialEnrollmentStore::begin(&local, begin(170, "foreign-receipt", 171)).unwrap();
    ProviderCredentialEnrollmentStore::issue_ticket_attempt(&local, ticket(170, 1, 172, 173))
        .unwrap();
    let persisted =
        ProviderCredentialEnrollmentStore::load_operation(&local, operation(170)).unwrap();
    let (foreign, _) = runne_provider::CredentialEnrollmentAuthorityPair::new().split();
    let receipt = foreign
        .hydrate_issued_credential_ticket_attempt(
            persisted,
            CredentialTicketAttempt::new(1).unwrap(),
            100,
            200,
        )
        .unwrap();
    let claim = seal_claim(
        &local,
        ClaimCredentialOperation::new(receipt, digest(172), digest(173), digest(174), 1, 1)
            .unwrap(),
    );

    assert_eq!(
        ProviderCredentialEnrollmentStore::claim(&local, claim).unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    assert_eq!(ticket_state(&local, 170, 1), "ISSUED");
}

#[test]
fn credential_online_restart_hydrates_same_owner_receipt_for_claim() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("restart-receipt.sqlite");
    let initial = open_test_store(&path, 100);
    ProviderCredentialEnrollmentStore::begin(&initial, begin(180, "restart-receipt", 181)).unwrap();
    drop(initial);

    let restarted = open_test_store(&path, 100);
    let receipt = ProviderCredentialEnrollmentStore::issue_ticket_attempt(
        &restarted,
        ticket(180, 1, 182, 183),
    )
    .unwrap();
    let claim = seal_claim(
        &restarted,
        ClaimCredentialOperation::new(receipt, digest(182), digest(183), digest(184), 1, 1)
            .unwrap(),
    );

    assert_eq!(
        ProviderCredentialEnrollmentStore::claim(&restarted, claim)
            .unwrap()
            .operation_id(),
        operation(180)
    );
}
