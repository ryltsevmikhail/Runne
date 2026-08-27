use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    BeginCredentialOperation, BindCredentialReadback, CompleteCredentialOperation,
    CredentialEnrollmentAuthorityPair, CredentialFence, CredentialInstallationOwnerId,
    CredentialLifecycleRevision, CredentialNativeEffectDisposition, CredentialOperationAction,
    CredentialReadbackDisposition, ObserveNativeEffect, ProviderCredentialEnrollmentStore,
};

use super::{
    online_claim_test_support::seal_claim,
    online_test_support::{claim, digest, operation, provider, store, ticket},
};

#[test]
fn credential_online_legacy_cleanup_persists_and_replays_without_head_transition() {
    let store = store();
    prepare_legacy_source_cleanup(&store);
    let before = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();

    let receipt = ProviderCredentialEnrollmentStore::complete_with_receipt(
        &store,
        legacy_source_cleanup_completion(),
    )
    .unwrap();
    let persisted: (i64, i64) = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*), readiness_observation_id IS NULL
             FROM provider_credential_completion_receipts WHERE operation_id=?1",
            [operation(90).as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();

    assert_eq!(persisted, (1, 1));
    assert_eq!(receipt.successor(), before);
    assert_eq!(
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap(),
        before
    );
    assert_eq!(
        ProviderCredentialEnrollmentStore::complete_with_receipt(
            &store,
            legacy_source_cleanup_completion(),
        )
        .unwrap(),
        receipt
    );
}

fn prepare_legacy_source_cleanup(store: &super::SqliteProviderCredentialLifecycleStore) {
    ProviderCredentialEnrollmentStore::begin(store, legacy_source_cleanup_begin()).unwrap();
    ProviderCredentialEnrollmentStore::issue_ticket_attempt(store, ticket(90, 1, 92, 93)).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        store,
        seal_claim(store, claim(store, 90, 1, 92, 93, 94)),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        store,
        ObserveNativeEffect::new(
            operation(90),
            CredentialNativeEffectDisposition::PossibleEffect,
        ),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        store,
        BindCredentialReadback::new(
            operation(90),
            CredentialReadbackDisposition::ExactAbsence,
            digest(95),
        )
        .unwrap(),
    )
    .unwrap();
}

fn legacy_source_cleanup_begin() -> BeginCredentialOperation {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let manifest = measurements.release_manifest_digest([92; 32]).unwrap();
    let qualified_release = measurements
        .issue_qualified_credential_release_tuple(manifest)
        .unwrap();
    BeginCredentialOperation::new(
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
    .with_qualified_release_tuple(qualified_release)
}

fn legacy_source_cleanup_completion() -> CompleteCredentialOperation {
    CompleteCredentialOperation::new(
        operation(90),
        BindCredentialReadback::new(
            operation(90),
            CredentialReadbackDisposition::ExactAbsence,
            digest(95),
        )
        .unwrap(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
    )
    .unwrap()
}
