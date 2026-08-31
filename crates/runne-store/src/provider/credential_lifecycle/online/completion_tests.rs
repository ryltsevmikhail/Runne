use runne_provider::{
    BindCredentialReadback, CompleteCredentialOperation, CredentialBindingDigest, CredentialFence,
    CredentialLifecycleRevision, CredentialNativeEffectDisposition, CredentialReadbackDisposition,
    CredentialReadinessDisposition, CredentialReadinessObservation, CredentialReadinessRevision,
    CredentialVersionRef, ObserveNativeEffect, ProviderCredentialEnrollmentStore,
};

use super::online_test_support::{
    admit_claim, complete_pair, digest, operation, provider, revoke, store,
};

#[test]
fn credential_online_pair_completion_persists_readiness_atomically() {
    let store = store();
    prepare_pair(&store);
    let active = CredentialVersionRef::new(provider(), 1).unwrap();

    ProviderCredentialEnrollmentStore::complete(&store, completion()).unwrap();

    let persisted = store.connection.lock().unwrap().query_row(
        "SELECT lifecycle_revision, readiness_revision, disposition,
                active_binding_digest, release_tuple_digest, operation_id
         FROM provider_credential_readiness_observations WHERE observation_id=?1",
        [operation(91).as_bytes().as_slice()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        },
    );
    assert_eq!(
        persisted.unwrap(),
        (
            2,
            2,
            "READY".to_owned(),
            active.ref_digest().to_vec(),
            digest(92).as_bytes().to_vec(),
            operation(90).as_bytes().to_vec(),
        )
    );
}

#[test]
fn credential_online_completion_returns_the_persisted_receipt() {
    let store = store();
    prepare_pair(&store);

    let receipt = ProviderCredentialEnrollmentStore::complete_with_receipt(&store, completion())
        .unwrap();

    assert_eq!(receipt.operation_id(), operation(90));
}

#[test]
fn credential_online_pair_fixture_persists_its_authority_issued_qualified_tuple() {
    let store = store();

    complete_pair(&store, 90, "qualified-pair");

    let tuple: Vec<u8> = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT qualified_release_tuple_digest FROM provider_credential_operations
             WHERE operation_id=?1",
            [operation(90).as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tuple, [92; 32]);
    assert_ne!(tuple, vec![0; 32]);
}

#[test]
fn credential_online_pair_writes_a_non_expiring_v16_compatibility_mirror() {
    let store = store();
    prepare_pair(&store);

    let lifecycle = ProviderCredentialEnrollmentStore::complete(&store, completion()).unwrap();
    let mirror: (String, Vec<u8>, i64, i64) = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT lifecycle_state, lease_owner, lease_expires_at, lease_fencing_token
             FROM provider_credential_versions
             WHERE provider_id='openai' AND credential_version=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();

    assert_eq!(mirror.0, "ACTIVE");
    assert_eq!(mirror.1, b"RUNNE_V24_MIRROR");
    assert_eq!(mirror.2, i64::MAX);
    assert_eq!(mirror.3, 1);
    assert_ne!(mirror.3 as u64, lifecycle.fence().get());
    let lease = store.active_lease(&provider()).unwrap().unwrap();
    assert_eq!(
        store.authorize_dispatch(&lease, 100).unwrap_err(),
        runne_provider::CredentialLifecycleError::StaleLease
    );
}

#[test]
fn credential_online_completed_pair_replays_matching_readiness_observation() {
    let store = store();
    prepare_pair(&store);

    let first = ProviderCredentialEnrollmentStore::complete(&store, completion()).unwrap();
    let replay = ProviderCredentialEnrollmentStore::complete(&store, completion()).unwrap();

    assert_eq!(replay, first);
}

#[test]
fn credential_online_completed_pair_rejects_replay_without_readiness() {
    let store = store();
    prepare_pair(&store);
    ProviderCredentialEnrollmentStore::complete(&store, completion()).unwrap();
    let before =
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();

    let replay = ProviderCredentialEnrollmentStore::complete(&store, plain_completion());

    assert_eq!(
        replay.unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    assert_eq!(
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap(),
        before
    );
}

#[test]
fn credential_online_pair_replay_returns_receipt_after_later_revoke() {
    let store = store();
    prepare_pair(&store);
    let first = ProviderCredentialEnrollmentStore::complete(&store, completion()).unwrap();
    ProviderCredentialEnrollmentStore::begin(&store, revoke(93, "later-revoke", 2, 2)).unwrap();

    let replay = ProviderCredentialEnrollmentStore::complete(&store, completion()).unwrap();

    assert_eq!(replay, first);
    assert_ne!(
        replay,
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap()
    );
}

#[test]
fn credential_online_pair_completion_requires_readiness_receipt() {
    let store = store();
    prepare_pair(&store);

    let result = ProviderCredentialEnrollmentStore::complete(&store, plain_completion());

    assert_eq!(
        result.unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    let lifecycle =
        ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider()).unwrap();
    assert!(lifecycle.active_version().is_none());
    assert_eq!(lifecycle.lifecycle_revision().get(), 1);
}

fn prepare_pair(store: &super::SqliteProviderCredentialLifecycleStore) {
    admit_claim(store, 90, "readiness");
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        store,
        ObserveNativeEffect::new(
            operation(90),
            CredentialNativeEffectDisposition::PossibleEffect,
        ),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(store, readback()).unwrap();
}

fn completion() -> CompleteCredentialOperation {
    let active = CredentialVersionRef::new(provider(), 1).unwrap();
    let active_digest = CredentialBindingDigest::from_measured(*active.ref_digest()).unwrap();
    let readiness = CredentialReadinessObservation::new(
        operation(91),
        Some(operation(90)),
        provider(),
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialReadinessRevision::new(2).unwrap(),
        CredentialReadinessDisposition::Ready,
        Some(active_digest),
        digest(92),
        100,
    )
    .unwrap();
    plain_completion().with_readiness_observation(readiness)
}

fn plain_completion() -> CompleteCredentialOperation {
    CompleteCredentialOperation::new(
        operation(90),
        readback(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
    )
    .unwrap()
}

fn readback() -> BindCredentialReadback {
    BindCredentialReadback::new(
        operation(90),
        CredentialReadbackDisposition::ExactVersion,
        digest(95),
    )
    .unwrap()
}
