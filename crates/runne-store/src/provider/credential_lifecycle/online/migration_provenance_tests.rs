use runne_provider::{CredentialLifecycleError, ProviderCredentialEnrollmentStore};

use super::online_test_support::{qualified_release, store};

#[test]
fn recovery_rejects_a_claimed_migration_without_persisted_binding_digest() {
    let store = store();
    let qualified_release = qualified_release(92);
    let connection = store.connection.lock().unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER provider_credential_migration_provenance_insert;
             DROP TRIGGER provider_credential_operation_insert_prepared",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provider_credential_authority_heads
             (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version)
             VALUES ('openai', 1, 1, 1, 1)",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provider_credential_operations
             (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
              expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest,
              migration_id, migration_phase, migration_old_tuple_digest, migration_new_tuple_digest,
              qualified_release_tuple_digest,
              created_at, updated_at)
             VALUES (?1, ?2, 'openai', 'WRITER_IDENTITY_MIGRATION_EFFECT', ?1, 'migration-missing',
                     1, 1, 'PREPARED', ?3, ?4, 'EFFECT', ?5, ?6, ?7, 100, 100)",
            rusqlite::params![
                [41_u8; 16],
                [42_u8; 32],
                [43_u8; 32],
                [46_u8; 16],
                [47_u8; 32],
                [48_u8; 32],
                qualified_release.digest().as_bytes().as_slice(),
            ],
        )
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER provider_credential_operation_transition")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_credential_operations
             SET state='CLAIMED', continuation_binding_digest=?1, process_release_binding_digest=?2
             WHERE operation_id=?3",
            rusqlite::params![[44_u8; 32], [45_u8; 32], [41_u8; 16]],
        )
        .unwrap();
    drop(connection);

    assert_eq!(
        ProviderCredentialEnrollmentStore::reconcile_online(&store, 100).unwrap_err(),
        CredentialLifecycleError::CorruptState
    );
}
