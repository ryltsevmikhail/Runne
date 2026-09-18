use runne_provider::{
    AttachCredentialProcess, CredentialLifecycleError, ProviderCredentialEnrollmentStore,
};

use super::online_test_support::{begin, digest, operation, store, ticket};

#[test]
fn ticket_issue_requires_the_exact_durable_writer_attachment() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(201, "attachment", 202)).unwrap();

    assert_eq!(
        ProviderCredentialEnrollmentStore::issue_ticket_attempt(&store, ticket(201, 1, 203, 204)),
        Err(CredentialLifecycleError::Conflict)
    );

    ProviderCredentialEnrollmentStore::attach_process(
        &store,
        AttachCredentialProcess::new(operation(201), digest(204)).unwrap(),
    )
    .unwrap();

    assert!(
        ProviderCredentialEnrollmentStore::issue_ticket_attempt(&store, ticket(201, 1, 203, 204),)
            .is_ok()
    );
    assert_eq!(
        ProviderCredentialEnrollmentStore::issue_ticket_attempt(&store, ticket(201, 2, 205, 206)),
        Err(CredentialLifecycleError::Conflict)
    );
}
