#[test]
fn installation_owner_id_is_required_typed_exact_and_immutable() {
    let connection = v24_connection();
    insert_head_for_test(&connection, "owner-shape");
    let insert = "INSERT INTO provider_credential_operations
        (operation_id, installation_owner_id, provider_id, action, command_id,
         idempotency_key, expected_lifecycle_revision, expected_credential_fence,
         state, begin_proof_digest, created_at, updated_at)
         VALUES (?1, ?2, 'owner-shape', 'LEGACY_SOURCE_CLEANUP', ?1, ?3, 1, 1,
                 'PREPARED', ?4, 1, 1)";

    assert!(connection
        .execute(
            "INSERT INTO provider_credential_operations
             (operation_id, provider_id, action, command_id, idempotency_key,
              expected_lifecycle_revision, expected_credential_fence, state,
              begin_proof_digest, created_at, updated_at)
             VALUES (?1, 'owner-shape', 'LEGACY_SOURCE_CLEANUP', ?1, 'owner-missing',
                     1, 1, 'PREPARED', ?2, 1, 1)",
            rusqlite::params![[1_u8; 16], [1_u8; 32]],
        )
        .is_err());
    for (operation, owner) in [
        (2_u8, rusqlite::types::Value::Blob(vec![0; 32])),
        (3, rusqlite::types::Value::Blob(vec![3; 31])),
        (4, rusqlite::types::Value::Text("owner-text".into())),
    ] {
        assert!(connection
            .execute(
                insert,
                rusqlite::params![
                    [operation; 16],
                    owner,
                    format!("owner-{operation}"),
                    [operation; 32]
                ],
            )
            .is_err());
    }
    connection
        .execute(
            insert,
            rusqlite::params![[5_u8; 16], [5_u8; 32], "owner-good", [5_u8; 32]],
        )
        .unwrap();
    assert!(connection
        .execute(
            "UPDATE provider_credential_operations SET installation_owner_id=?1
             WHERE operation_id=?2",
            rusqlite::params![[6_u8; 32], [5_u8; 16]],
        )
        .is_err());
}
