#[test]
fn v26_to_v27_registers_provenance_columns_and_rejects_fabrication() {
    let connection = Connection::open_in_memory().unwrap();
    initialize_released_v23(&connection);
    apply_migrations_internal(&connection, 26).unwrap();
    assert!(v26_matches(&connection, 26).unwrap());

    apply_migrations_internal(&connection, 27).unwrap();

    assert_eq!(current_schema_marker(&connection), 27);
    assert!(v27_operation_table_matches(&connection).unwrap());
    assert!(v27_trigger_catalog_matches(&connection).unwrap());
    assert!(v26_predecessor_matches_with(
        &connection,
        v27_operation_table_matches,
        v27_trigger_catalog_matches,
        false,
    )
    .unwrap());
    assert!(v27_matches(&connection, 27).unwrap());
    let columns = connection
        .prepare("SELECT name FROM pragma_table_info('provider_credential_operations')")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(columns.contains(&"broker_migration_binding_digest".to_owned()));
    assert!(columns.contains(&"claimed_ticket_attempt".to_owned()));
    connection
        .execute(
            "INSERT INTO provider_credential_authority_heads
             (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version)
             VALUES ('openai', 1, 1, 1, 1)",
            [],
        )
        .unwrap();
    assert!(connection.execute(
        "INSERT INTO provider_credential_operations
         (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
          expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest,
          migration_id, migration_phase, migration_old_tuple_digest, migration_new_tuple_digest,
          created_at, updated_at)
         VALUES (?1, ?2, 'openai', 'WRITER_IDENTITY_MIGRATION_EFFECT', ?1, 'missing',
                 1, 1, 'PREPARED', ?3, ?4, 'EFFECT', ?5, ?6, 1, 1)",
        rusqlite::params![[1_u8; 16], [2_u8; 32], [3_u8; 32], [4_u8; 16], [5_u8; 32], [6_u8; 32]],
    ).is_err());
    assert!(connection.execute(
        "INSERT INTO provider_credential_operations
         (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
          expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest,
          migration_id, migration_phase, migration_old_tuple_digest, migration_new_tuple_digest,
          broker_migration_binding_digest, created_at, updated_at)
         VALUES (?1, ?2, 'openai', 'WRITER_IDENTITY_MIGRATION_EFFECT', ?1, 'zero',
                 1, 1, 'PREPARED', ?3, ?4, 'EFFECT', ?5, ?6, zeroblob(32), 1, 1)",
        rusqlite::params![[7_u8; 16], [8_u8; 32], [9_u8; 32], [10_u8; 16], [11_u8; 32], [12_u8; 32]],
    ).is_err());
    assert!(connection.execute(
        "INSERT INTO provider_credential_operations
         (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
          expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest,
          broker_migration_binding_digest, created_at, updated_at)
         VALUES (?1, ?2, 'openai', 'LEGACY_SOURCE_CLEANUP', ?1, 'mixed',
                 1, 1, 'PREPARED', ?3, ?4, 1, 1)",
        rusqlite::params![[13_u8; 16], [14_u8; 32], [15_u8; 32], [16_u8; 32]],
    ).is_err());
}
