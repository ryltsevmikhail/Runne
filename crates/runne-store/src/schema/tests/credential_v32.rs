#[test]
fn v32_allows_only_the_linked_legacy_cleanup_to_overlap_import() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 32).unwrap();

    assert!(v32_matches(&connection, 32).unwrap());
    for name in V32_OPERATION_INDEXES {
        assert!(
            connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1)",
                    [name],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        );
    }
    connection
        .execute_batch("DROP INDEX provider_credential_one_pending_legacy_source_cleanup")
        .unwrap();
    assert!(!v32_matches(&connection, 32).unwrap());
}

#[test]
fn v32_permits_the_readback_verified_import_and_its_exact_cleanup_pair() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection.execute(
        "INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES ('cutover', 1, 1, 1, 1)",
        [],
    ).unwrap();
    connection.execute(
        "INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, begin_proof_expires_at_high_water, qualified_release_tuple_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'cutover', 'MIGRATE_LEGACY', ?1, 'cutover-import', 1, 1, 1, ?2, 'PREPARED', ?3, 10, ?4, 1, 1)",
        rusqlite::params![[1_u8; 16], [1_u8; 32], [2_u8; 32], [3_u8; 32]],
    ).unwrap();
    connection.execute(
        "UPDATE provider_credential_operations SET state = 'CLAIMED', continuation_binding_digest = ?1, process_release_binding_digest = ?2, updated_at = 2 WHERE operation_id = ?3",
        rusqlite::params![[3_u8; 32], [4_u8; 32], [1_u8; 16]],
    ).unwrap();
    connection.execute(
        "UPDATE provider_credential_operations SET state = 'NATIVE_EFFECT_OBSERVED', native_effect_disposition = 'observed', updated_at = 3 WHERE operation_id = ?1",
        [[1_u8; 16]],
    ).unwrap();
    connection.execute(
        "UPDATE provider_credential_operations SET state = 'READBACK_VERIFIED', readback_observation_digest = ?1, updated_at = 4 WHERE operation_id = ?2",
        rusqlite::params![[5_u8; 32], [1_u8; 16]],
    ).unwrap();
    connection.execute(
        "INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, begin_proof_expires_at_high_water, qualified_release_tuple_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'cutover', 'LEGACY_SOURCE_CLEANUP', ?1, 'cutover-cleanup', 2, 2, 'PREPARED', ?2, 10, ?3, 4, 4)",
        rusqlite::params![[6_u8; 16], [7_u8; 32], [3_u8; 32]],
    ).unwrap();
    assert!(connection.execute(
        "INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, begin_proof_expires_at_high_water, qualified_release_tuple_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'cutover', 'PAIR', ?1, 'cutover-second', 1, 1, 2, ?2, 'PREPARED', ?3, 10, ?4, 4, 4)",
        rusqlite::params![[8_u8; 16], [8_u8; 32], [9_u8; 32], [3_u8; 32]],
    ).is_err());
    connection.execute(
        "UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, active_credential_version = 1, active_ref_digest = ?1, legacy_import_consumed = 1, legacy_source_binding_digest = ?2, legacy_consumed_lifecycle_revision = 2, legacy_cleanup_operation_id = ?3 WHERE provider_id = 'cutover'",
        rusqlite::params![[1_u8; 32], [9_u8; 32], [6_u8; 16]],
    ).unwrap();
}
