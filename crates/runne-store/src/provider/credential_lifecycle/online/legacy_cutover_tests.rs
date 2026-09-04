use runne_domain::id::{CommandId, IdempotencyKey};
#[path = "legacy_cleanup_binding_tests.rs"]
mod cleanup_binding;
use runne_provider::{
    BeginCredentialOperation, BindCredentialReadback, ClaimCredentialOperation,
    CompleteCredentialOperation, CredentialFence, CredentialInstallationOwnerId,
    CredentialLifecycleRevision, CredentialNativeEffectDisposition, CredentialOperationAction,
    CredentialOperationState, CredentialReadbackDisposition, CredentialReadinessDisposition,
    CredentialReadinessObservation, CredentialReadinessRevision, CredentialVersionRef,
    ObserveNativeEffect, ProviderCredentialEnrollmentStore,
};

use super::{
    online_claim_test_support::seal_claim,
    online_test_support::{
        claim, digest, issue_ticket, operation, pair_completion, provider, qualified_release,
        store, ticket,
    },
};

#[test]
fn legacy_import_commits_its_barrier_receipt_and_cleanup_atomically() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, authorized_legacy_begin(&store)).unwrap();
    issue_ticket(&store, ticket(60, 1, 61, 62)).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        &store,
        seal_claim(&store, claim(&store, 60, 1, 61, 62, 63)),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(
            operation(60),
            CredentialNativeEffectDisposition::PossibleEffect,
        ),
    )
    .unwrap();
    let readback = BindCredentialReadback::new(
        operation(60),
        CredentialReadbackDisposition::ExactVersion,
        digest(65),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(&store, readback).unwrap();

    let receipt =
        ProviderCredentialEnrollmentStore::complete_with_receipt(&store, pair_completion(60))
            .unwrap();
    let persisted: (String, i64, i64, i64, Vec<u8>, i64, i64, String) = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT import.state, head.legacy_import_consumed, head.lifecycle_revision,
                    head.credential_fence, head.legacy_source_binding_digest,
                    cleanup.expected_lifecycle_revision, cleanup.expected_credential_fence,
                    cleanup.state
             FROM provider_credential_operations AS import
             JOIN provider_credential_authority_heads AS head ON head.provider_id=import.provider_id
             JOIN provider_credential_operations AS cleanup ON cleanup.operation_id=head.legacy_cleanup_operation_id
             WHERE import.operation_id=?1",
            [operation(60).as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                    row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(receipt.operation_id(), operation(60));
    assert_eq!(
        persisted,
        (
            "COMPLETED".to_owned(),
            1,
            2,
            2,
            digest(65).as_bytes().to_vec(),
            2,
            2,
            "PREPARED".to_owned()
        )
    );
    assert_eq!(
        ProviderCredentialEnrollmentStore::load_operation(&store, operation(60))
            .unwrap()
            .state(),
        CredentialOperationState::Completed
    );
    assert_eq!(
        ProviderCredentialEnrollmentStore::complete_with_receipt(&store, pair_completion(60))
            .unwrap(),
        receipt
    );
}

#[test]
fn legacy_import_rolls_back_the_barrier_when_receipt_validation_rejects_readiness() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, authorized_legacy_begin(&store)).unwrap();
    issue_ticket(&store, ticket(60, 1, 61, 62)).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        &store,
        seal_claim(&store, claim(&store, 60, 1, 61, 62, 63)),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(
            operation(60),
            CredentialNativeEffectDisposition::PossibleEffect,
        ),
    )
    .unwrap();
    let readback = BindCredentialReadback::new(
        operation(60),
        CredentialReadbackDisposition::ExactVersion,
        digest(65),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(&store, readback).unwrap();

    let active = CredentialVersionRef::new(provider(), 1).unwrap();
    let readiness = CredentialReadinessObservation::new(
        operation(61),
        Some(operation(60)),
        provider(),
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialReadinessRevision::new(2).unwrap(),
        CredentialReadinessDisposition::Ready,
        Some(digest_from(&active)),
        digest(66),
        100,
    )
    .unwrap();
    let rejected = pair_completion(60).with_readiness_observation(readiness);
    assert_eq!(
        ProviderCredentialEnrollmentStore::complete_with_receipt(&store, rejected).unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    let persisted: (i64, i64) = store.connection.lock().unwrap().query_row(
        "SELECT legacy_import_consumed, (SELECT COUNT(*) FROM provider_credential_operations WHERE action='LEGACY_SOURCE_CLEANUP') FROM provider_credential_authority_heads WHERE provider_id='openai'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(persisted, (0, 0));
}

#[test]
fn linked_legacy_cleanup_completes_without_reopening_the_consumed_barrier() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, authorized_legacy_begin(&store)).unwrap();
    issue_ticket(&store, ticket(60, 1, 61, 62)).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        &store,
        seal_claim(&store, claim(&store, 60, 1, 61, 62, 63)),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(
            operation(60),
            CredentialNativeEffectDisposition::PossibleEffect,
        ),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        &store,
        BindCredentialReadback::new(
            operation(60),
            CredentialReadbackDisposition::ExactVersion,
            digest(65),
        )
        .unwrap(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::complete_with_receipt(&store, pair_completion(60)).unwrap();

    let cleanup = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT legacy_cleanup_operation_id
             FROM provider_credential_authority_heads WHERE provider_id='openai'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .unwrap();
    let cleanup =
        runne_provider::CredentialOperationId::from_bytes(cleanup.try_into().unwrap()).unwrap();
    let issued = issue_ticket(
        &store,
        runne_provider::IssueCredentialTicketDigest::new(cleanup, digest(71), digest(72), 100)
            .unwrap(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::claim(
        &store,
        seal_claim(
            &store,
            ClaimCredentialOperation::new(issued, digest(71), digest(72), digest(73), 1, 1)
                .unwrap(),
        ),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(cleanup, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    let readback = BindCredentialReadback::new(
        cleanup,
        CredentialReadbackDisposition::ExactAbsence,
        digest(74),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(&store, readback).unwrap();
    ProviderCredentialEnrollmentStore::complete_with_receipt(
        &store,
        CompleteCredentialOperation::new(
            cleanup,
            BindCredentialReadback::new(
                cleanup,
                CredentialReadbackDisposition::ExactAbsence,
                digest(74),
            )
            .unwrap(),
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialFence::new(2).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();

    let persisted: (i64, i64, String) = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT head.legacy_import_consumed, head.legacy_cleanup_operation_id=?1, cleanup.state
             FROM provider_credential_authority_heads AS head
             JOIN provider_credential_operations AS cleanup
               ON cleanup.operation_id=head.legacy_cleanup_operation_id
             WHERE head.provider_id='openai'",
            [cleanup.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(persisted, (1, 1, "COMPLETED".to_owned()));
}

fn digest_from(version: &CredentialVersionRef) -> runne_provider::CredentialBindingDigest {
    runne_provider::CredentialBindingDigest::from_measured(*version.ref_digest()).unwrap()
}

fn legacy_begin() -> BeginCredentialOperation {
    let provider = provider();
    BeginCredentialOperation::new(
        CommandId::from_bytes([60; 16]),
        IdempotencyKey::new("legacy-cutover").unwrap(),
        operation(60),
        CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
        provider.clone(),
        CredentialOperationAction::MigrateLegacy,
        Some(CredentialVersionRef::new(provider, 1).unwrap()),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(64),
        200,
    )
    .unwrap()
    .with_qualified_release_tuple(qualified_release(92))
}

fn authorized_legacy_begin(
    store: &super::SqliteProviderCredentialLifecycleStore,
) -> BeginCredentialOperation {
    let input = legacy_begin();
    let authorization = store
        .enrollment_authority
        .issue_legacy_import_authorization(&input)
        .unwrap();
    input
        .with_legacy_import_authorization(authorization)
        .unwrap()
}
