fn insert_target_test_head(connection: &Connection, provider: &str) {
    connection
        .execute(
            "INSERT INTO provider_credential_authority_heads
             (provider_id, lifecycle_revision, credential_fence, readiness_revision,
              next_credential_version)
             VALUES (?1, 1, 1, 1, 1)",
            [provider],
        )
        .unwrap();
}

fn activate_target_test_head(connection: &Connection, provider: &str, operation: u8) {
    insert_target_test_head(connection, provider);
    insert_allocated_operation(connection, operation, provider, 1, 1, Some(1)).unwrap();
    readback_verified_operation(connection, operation);
    connection
        .execute(
            "UPDATE provider_credential_authority_heads
             SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2,
                 active_credential_version = 1, active_ref_digest = ?1
             WHERE provider_id = ?2",
            rusqlite::params![[operation; 32], provider],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE provider_credential_operations
             SET state = 'COMPLETED', terminal_disposition = 'completed',
                 updated_at = updated_at + 1
             WHERE operation_id = ?1",
            [[operation; 16]],
        )
        .unwrap();
}

#[test]
fn destructive_operations_require_an_exact_immutable_target() {
    for action in ["REVOKE", "RETIRED_VERSION_CLEANUP"] {
        let connection = v24_connection();
        if action == "REVOKE" {
            activate_target_test_head(&connection, "target-required", 9);
        } else {
            insert_target_test_head(&connection, "target-required");
        }

        let result = connection.execute(
            "INSERT INTO provider_credential_operations
             (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
              expected_lifecycle_revision, expected_credential_fence, state,
              begin_proof_digest, created_at, updated_at)
             VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'target-required', ?2, ?1, ?3, ?4, ?4, 'PREPARED', ?5, 1, 1)",
            rusqlite::params![
                [1_u8; 16],
                action,
                action,
                if action == "REVOKE" { 2 } else { 1 },
                [1_u8; 32]
            ],
        );

        assert!(result.is_err(), "{action} accepted without an immutable target");
    }
}

#[test]
fn exact_target_is_action_scoped_and_write_once() {
    let connection = v24_connection();
    activate_target_test_head(&connection, "target-owned", 8);
    let insert = "INSERT INTO provider_credential_operations
        (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
         expected_lifecycle_revision, expected_credential_fence,
         target_credential_version, target_ref_digest, state,
         begin_proof_digest, created_at, updated_at)
        VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'target-owned', ?2, ?1, ?3, 2, 2, 1, ?4, 'PREPARED', ?5, 1, 1)";

    connection
        .execute(
            insert,
            rusqlite::params![
                [2_u8; 16],
                "REVOKE",
                "target-revoke",
                [8_u8; 32],
                [2_u8; 32]
            ],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                "UPDATE provider_credential_operations
                 SET target_credential_version = 2, target_ref_digest = ?1
                 WHERE operation_id = ?2",
                rusqlite::params![[3_u8; 32], [2_u8; 16]],
            )
            .is_err()
    );

    assert!(
        connection
            .execute(
                insert,
                rusqlite::params![
                    [3_u8; 16],
                    "PAIR",
                    "target-pair",
                    [3_u8; 32],
                    [3_u8; 32]
                ],
            )
            .is_err()
    );
}

#[test]
fn revoke_target_must_match_the_exact_active_reference() {
    let connection = v24_connection();
    activate_target_test_head(&connection, "target-canonical", 7);

    let result = connection.execute(
        "INSERT INTO provider_credential_operations
         (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
          expected_lifecycle_revision, expected_credential_fence,
          target_credential_version, target_ref_digest, state,
          begin_proof_digest, created_at, updated_at)
         VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'target-canonical', 'REVOKE', ?1, 'target-canonical',
                 2, 2, 1, ?2, 'PREPARED', ?3, 1, 1)",
        rusqlite::params![[4_u8; 16], [0xFF_u8; 32], [4_u8; 32]],
    );

    assert!(result.is_err());
    insert_target_test_head(&connection, "cleanup-owned");
    connection
        .execute(
            "INSERT INTO provider_credential_versions
             (provider_id, credential_version, ref_digest, lifecycle_state)
             VALUES ('cleanup-owned', 7, ?1, 'PREPARED')",
            [[5_u8; 32]],
        )
        .unwrap();
    connection.execute("UPDATE provider_credential_versions SET lifecycle_state='ACTIVE', lease_owner=?1, lease_expires_at=9223372036854775807, lease_fencing_token=1 WHERE provider_id='cleanup-owned' AND credential_version=7", [[7_u8; 16]]).unwrap();
    connection.execute("UPDATE provider_credential_versions SET lifecycle_state='RETIRED', revocation_fence=1 WHERE provider_id='cleanup-owned' AND credential_version=7", []).unwrap();
    connection
        .execute(
            "INSERT INTO provider_credential_operations
             (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
              expected_lifecycle_revision, expected_credential_fence,
              target_credential_version, target_ref_digest, state,
              begin_proof_digest, created_at, updated_at)
             VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'cleanup-owned', 'RETIRED_VERSION_CLEANUP', ?1,
                     'cleanup-owned', 1, 1, 7, ?2, 'PREPARED', ?3, 1, 1)",
            rusqlite::params![[17_u8; 16], [5_u8; 32], [17_u8; 32]],
        )
        .unwrap();
}

#[test]
fn retired_cleanup_target_must_exist_in_the_native_version_mirror() {
    let connection = v24_connection();
    insert_target_test_head(&connection, "cleanup-owned");

    let result = connection.execute(
        "INSERT INTO provider_credential_operations
         (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
          expected_lifecycle_revision, expected_credential_fence,
          target_credential_version, target_ref_digest, state,
          begin_proof_digest, created_at, updated_at)
         VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'cleanup-owned', 'RETIRED_VERSION_CLEANUP', ?1,
                 'cleanup-missing', 1, 1, 7, ?2, 'PREPARED', ?3, 1, 1)",
        rusqlite::params![[5_u8; 16], [5_u8; 32], [6_u8; 32]],
    );

    assert!(result.is_err());
}
