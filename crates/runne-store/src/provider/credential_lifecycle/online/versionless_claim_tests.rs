use runne_provider::{
    ClaimCredentialOperation, CredentialOperationAction, CredentialOperationState,
    ProviderCredentialEnrollmentStore,
};

use super::online_claim_test_support::seal_claim;
use super::online_test_support::{digest, store, ticket};

#[test]
fn every_versionless_action_can_win_the_durable_claim_cas() {
    for (id, _action, sql_action, phase) in [
        (
            41,
            CredentialOperationAction::LegacySourceCleanup,
            "LEGACY_SOURCE_CLEANUP",
            None,
        ),
        (
            42,
            CredentialOperationAction::WriterIdentityMigrationEffect,
            "WRITER_IDENTITY_MIGRATION_EFFECT",
            Some("EFFECT"),
        ),
        (
            43,
            CredentialOperationAction::WriterIdentityMigrationVerify,
            "WRITER_IDENTITY_MIGRATION_VERIFY",
            Some("VERIFY"),
        ),
    ] {
        let store = store();
        insert_operation(&store, id, sql_action, phase);
        let receipt = ProviderCredentialEnrollmentStore::issue_ticket_attempt(
            &store,
            ticket(id, 1, id.wrapping_add(1), id.wrapping_add(2)),
        )
        .unwrap();
        let claim = ClaimCredentialOperation::new(
            receipt,
            digest(id.wrapping_add(1)),
            digest(id.wrapping_add(2)),
            digest(id.wrapping_add(3)),
            1,
            1,
        )
        .unwrap();

        let snapshot =
            ProviderCredentialEnrollmentStore::claim(&store, seal_claim(&store, claim)).unwrap();
        assert_eq!(snapshot.state(), CredentialOperationState::Claimed);
    }
}

fn insert_operation(
    store: &super::SqliteProviderCredentialLifecycleStore,
    id: u8,
    action: &str,
    phase: Option<&str>,
) {
    let migration_id = phase.map(|_| vec![90_u8; 16]);
    let old_tuple = phase.map(|_| vec![91_u8; 32]);
    let new_tuple = phase.map(|_| vec![92_u8; 32]);
    let connection = store.connection.lock().unwrap();
    connection
        .execute(
            "INSERT INTO provider_credential_authority_heads
             (provider_id, lifecycle_revision, credential_fence,
              readiness_revision, next_credential_version)
             VALUES ('openai', 1, 1, 1, 1)",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provider_credential_operations
             (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
              expected_lifecycle_revision, expected_credential_fence, state,
              begin_proof_digest, begin_proof_expires_at_high_water, migration_id, migration_phase,
              migration_old_tuple_digest, migration_new_tuple_digest,
              created_at, updated_at)
             VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'openai', ?2, ?1, ?3, 1, 1, 'PREPARED', ?4, 200,
                     ?5, ?6, ?7, ?8, 100, 100)",
            rusqlite::params![
                [id; 16],
                action,
                format!("versionless-{id}"),
                [id; 32],
                migration_id,
                phase,
                old_tuple,
                new_tuple,
            ],
        )
        .unwrap();
}
