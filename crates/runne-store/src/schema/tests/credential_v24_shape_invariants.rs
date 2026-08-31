#[test]
fn destructive_operation_cannot_consume_an_allocated_version() {
    let connection = v24_connection();
    activate_target_test_head(&connection, "shape-revoke", 31);
    let before: i64 = connection
        .query_row(
            "SELECT next_credential_version
             FROM provider_credential_authority_heads
             WHERE provider_id='shape-revoke'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    let result = connection.execute(
        "INSERT INTO provider_credential_operations
         (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
          expected_lifecycle_revision, expected_credential_fence,
          allocated_credential_version, allocated_ref_digest,
          target_credential_version, target_ref_digest, state,
          begin_proof_digest, created_at, updated_at)
         VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'shape-revoke', 'REVOKE', ?1, 'shape-revoke',
                 2, 2, ?2, ?3, 1, ?4, 'PREPARED', ?5, 1, 1)",
        rusqlite::params![
            [32_u8; 16],
            before,
            [32_u8; 32],
            [31_u8; 32],
            [33_u8; 32]
        ],
    );

    assert!(result.is_err());
    assert_eq!(
        connection
            .query_row(
                "SELECT next_credential_version
                 FROM provider_credential_authority_heads
                 WHERE provider_id='shape-revoke'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        before
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_credential_operations
                 WHERE operation_id=?1",
                [[32_u8; 16]],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}
