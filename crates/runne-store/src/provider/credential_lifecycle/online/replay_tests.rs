use runne_provider::{
    BindCredentialReadback, CredentialNativeEffectDisposition, CredentialReadbackDisposition,
    ObserveNativeEffect, ProviderCredentialEnrollmentStore,
};

use super::online_test_support::{admit_claim, begin, digest, operation, pair_completion, store};

#[test]
fn credential_online_completed_pair_replays_safe_lifecycle_snapshot() {
    let store = store();
    admit_claim(&store, 70, "complete-replay");
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(
            operation(70),
            CredentialNativeEffectDisposition::PossibleEffect,
        ),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(&store, readback(70)).unwrap();

    let first = ProviderCredentialEnrollmentStore::complete(&store, pair_completion(70)).unwrap();
    let replay = ProviderCredentialEnrollmentStore::complete(&store, pair_completion(70)).unwrap();

    assert_eq!(replay, first);
}

#[test]
fn corrupt_existing_operation_is_not_absent_and_does_not_mutate_head() {
    let store = store();
    ProviderCredentialEnrollmentStore::begin(&store, begin(71, "corrupt-replay", 72)).unwrap();
    let connection = store.connection.lock().unwrap();
    connection
        .execute_batch("DROP TRIGGER provider_credential_operation_transition")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_credential_operations SET allocated_ref_digest=?1 WHERE operation_id=?2",
            rusqlite::params![[99_u8; 32], operation(71).as_bytes().as_slice()],
        )
        .unwrap();
    let before: (i64, i64, i64) = connection
        .query_row(
            "SELECT next_credential_version, observed_at_high_water,
                    (SELECT COUNT(*) FROM provider_credential_operations)
             FROM provider_credential_authority_heads WHERE provider_id=?1",
            [super::online_test_support::provider().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    drop(connection);

    assert_eq!(
        ProviderCredentialEnrollmentStore::begin(&store, begin(71, "corrupt-replay", 72))
            .unwrap_err(),
        runne_provider::CredentialLifecycleError::CorruptState
    );
    let connection = store.connection.lock().unwrap();
    let after: (i64, i64, i64) = connection
        .query_row(
            "SELECT next_credential_version, observed_at_high_water,
                    (SELECT COUNT(*) FROM provider_credential_operations)
             FROM provider_credential_authority_heads WHERE provider_id=?1",
            [super::online_test_support::provider().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(after, before);
}

fn readback(operation_id: u8) -> BindCredentialReadback {
    BindCredentialReadback::new(
        operation(operation_id),
        CredentialReadbackDisposition::ExactVersion,
        digest(operation_id.wrapping_add(5)),
    )
    .unwrap()
}
