use runne_provider::{
    ClaimCredentialOperation, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialOperationState, CredentialProcessBinding, ProviderCredentialEnrollmentStore,
    WriterIdentityMigrationPhase,
};

use super::online_claim_test_support::seal_claim;
use super::online_test_support::{digest, issue_ticket, qualified_release, store, ticket};

#[test]
fn versionless_claim_requires_legacy_binding_but_accepts_bound_migration() {
    for (id, action, sql_action, phase) in [
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
        let receipt = issue_ticket(
            &store,
            ticket(id, 1, id.wrapping_add(1), id.wrapping_add(2)),
        );
        if action == CredentialOperationAction::LegacySourceCleanup {
            assert_eq!(receipt, Err(runne_provider::CredentialLifecycleError::Conflict));
            assert_eq!(store.load_operation(CredentialOperationId::from_bytes([id; 16]).unwrap())
                .unwrap().state(), CredentialOperationState::Prepared);
            continue;
        }
        let receipt = receipt.unwrap();
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
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let migration = phase.map(|phase| {
        let phase = match phase {
            "EFFECT" => WriterIdentityMigrationPhase::OldWriterEffect,
            "VERIFY" => WriterIdentityMigrationPhase::NewWriterVerify,
            _ => unreachable!("fixture phase is closed"),
        };
        let process = CredentialProcessBinding::new(
            measurements
                .writer_process_start_identity([id; 32])
                .unwrap(),
            measurements
                .writer_process_handle_identity([id.wrapping_add(10); 32])
                .unwrap(),
        );
        measurements
            .issue_credential_release_migration_binding(
                CredentialOperationId::from_bytes([90; 16]).unwrap(),
                phase,
                digest(91),
                digest(92),
                digest(93),
                digest(94),
                1,
                CredentialLifecycleRevision::new(1).unwrap(),
                CredentialFence::new(1).unwrap(),
                process,
            )
            .unwrap()
    });
    let migration_id = migration
        .as_ref()
        .map(|binding| binding.migration_id().as_bytes().to_vec());
    let old_tuple = migration
        .as_ref()
        .map(|binding| binding.old_tuple_digest().as_bytes().to_vec());
    let new_tuple = migration
        .as_ref()
        .map(|binding| binding.new_tuple_digest().as_bytes().to_vec());
    let migration_binding = migration
        .as_ref()
        .map(|binding| binding.digest().as_bytes().to_vec());
    let qualified_release = qualified_release(92);
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
              broker_migration_binding_digest,
              qualified_release_tuple_digest,
              created_at, updated_at)
             VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'openai', ?2, ?1, ?3, 1, 1, 'PREPARED', ?4, 200,
                     ?5, ?6, ?7, ?8, ?9, ?10, 100, 100)",
            rusqlite::params![
                [id; 16],
                action,
                format!("versionless-{id}"),
                [id; 32],
                migration_id,
                phase,
                old_tuple,
                new_tuple,
                migration_binding,
                qualified_release.digest().as_bytes().as_slice(),
            ],
        )
        .unwrap();
}
