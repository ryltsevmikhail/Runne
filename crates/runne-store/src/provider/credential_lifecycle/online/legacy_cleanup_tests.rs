use super::online_test_support::{
    digest, issue_ticket, operation, provider, qualified_release, store, ticket,
};
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    BeginCredentialOperation, CredentialFence, CredentialInstallationOwnerId,
    CredentialLifecycleError, CredentialLifecycleRevision, CredentialOperationAction,
    CredentialOperationState, ProviderCredentialEnrollmentStore,
};

#[test]
fn credential_online_unbound_legacy_cleanup_is_inspectable_but_cannot_get_ticket() {
    let store = store();
    let begin = BeginCredentialOperation::new(
        CommandId::from_bytes([110; 16]),
        IdempotencyKey::new("legacy-source-cleanup").unwrap(),
        operation(90),
        CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
        provider(),
        CredentialOperationAction::LegacySourceCleanup,
        None,
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(91),
        200,
    )
    .unwrap()
    .with_qualified_release_tuple(qualified_release(92));
    store.begin(begin).unwrap();
    let before = store.lifecycle_snapshot(&provider()).unwrap();
    let snapshot = store.load_operation(operation(90)).unwrap();
    assert!(snapshot.metadata().legacy_cleanup_binding().is_none());
    assert_eq!(snapshot.state(), CredentialOperationState::Prepared);
    assert_eq!(
        issue_ticket(&store, ticket(90, 1, 92, 93)),
        Err(CredentialLifecycleError::Conflict)
    );
    assert_eq!(store.lifecycle_snapshot(&provider()).unwrap(), before);
    let effects: (i64, i64, i64) = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_credential_process_attachments),
         (SELECT COUNT(*) FROM provider_credential_ticket_attempts),
         (SELECT COUNT(*) FROM provider_credential_completion_receipts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(effects, (0, 0, 0));
}
