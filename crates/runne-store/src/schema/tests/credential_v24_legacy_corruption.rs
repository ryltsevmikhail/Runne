#[test]
fn v24_rejects_noncanonical_legacy_provider_atomically() {
    let conn = Connection::open_in_memory().unwrap();
    apply_migrations_through_v23_for_test(&conn).unwrap();
    conn.execute("INSERT INTO provider_credential_versions VALUES ('bad\nprovider', 1, ?1, 'PREPARED', NULL, NULL, NULL, 0, NULL)", [[1_u8; 32]]).unwrap();
    assert!(apply_migrations(&conn).is_err());
    assert_eq!(current_schema_marker(&conn), 23);
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM provider_credential_versions WHERE provider_id = 'bad\nprovider'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'provider_credential_authority_heads'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn v24_rejects_wrong_legacy_digest_storage_atomically() {
    let conn = Connection::open_in_memory().unwrap();
    apply_migrations_through_v23_for_test(&conn).unwrap();
    conn.execute("INSERT INTO provider_credential_versions VALUES ('legacy-text-digest', 1, ?1, 'PREPARED', NULL, NULL, NULL, 0, NULL)", ["x".repeat(32)]).unwrap();
    assert!(apply_migrations(&conn).is_err());
    assert_eq!(current_schema_marker(&conn), 23);
    assert_eq!(conn.query_row("SELECT typeof(ref_digest) FROM provider_credential_versions WHERE provider_id = 'legacy-text-digest'", [], |row| row.get::<_, String>(0)).unwrap(), "text");
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'provider_credential_authority_heads'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn consumed_legacy_barrier_is_immutable_and_requires_live_cleanup() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "barrier");
    conn.execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, 'barrier', 'MIGRATE_LEGACY', ?1, 'barrier-migration', 1, 1, 1, ?2, 'PREPARED', ?3, 1, 1)", rusqlite::params![[91_u8; 16], [91_u8; 32], [92_u8; 32]]).unwrap();
    terminal_operation(&conn, 91);
    conn.execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, 'barrier', 'LEGACY_SOURCE_CLEANUP', ?1, 'barrier-cleanup', 1, 1, 2, ?2, 'PREPARED', ?3, 1, 1)", rusqlite::params![[92_u8; 16], [92_u8; 32], [93_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET legacy_import_consumed = 1, legacy_source_binding_digest = ?1, legacy_consumed_lifecycle_revision = 2, legacy_cleanup_operation_id = ?2, lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, next_credential_version = 3, active_credential_version = 1, active_ref_digest = ?3 WHERE provider_id = 'barrier'", rusqlite::params![[94_u8; 32], [92_u8; 16], [91_u8; 32]]).unwrap();
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET legacy_source_binding_digest = NULL WHERE provider_id = 'barrier'", []).is_err());
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET legacy_cleanup_operation_id = NULL WHERE provider_id = 'barrier'", []).is_err());

    let conn = v24_connection();
    insert_head_for_test(&conn, "tombstone-barrier");
    conn.execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, 'tombstone-barrier', 'LEGACY_SOURCE_CLEANUP', ?1, 'tombstone-cleanup', 1, 1, 1, ?2, 'PREPARED', ?3, 1, 1)", rusqlite::params![[94_u8; 16], [94_u8; 32], [95_u8; 32]]).unwrap();
    terminal_operation(&conn, 94);
    conn.execute("UPDATE provider_credential_operations SET state = 'TOMBSTONED', tombstone_digest = ?1, updated_at = updated_at + 1 WHERE operation_id = ?2", rusqlite::params![[96_u8; 32], [94_u8; 16]]).unwrap();
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET legacy_import_consumed = 1, legacy_source_binding_digest = ?1, legacy_consumed_lifecycle_revision = 2, legacy_cleanup_operation_id = ?2, lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, next_credential_version = 2, active_credential_version = 1, active_ref_digest = ?3 WHERE provider_id = 'tombstone-barrier'", rusqlite::params![[97_u8; 32], [94_u8; 16], [94_u8; 32]]).is_err());
}
