#[test]
fn pair_activation_requires_exact_readback_state() {
    for state in ["PREPARED", "CLAIMED", "NATIVE_EFFECT_OBSERVED"] {
        let conn = v24_connection();
        insert_head_for_test(&conn, "pair-state");
        insert_allocated_operation(&conn, 101, "pair-state", 1, 1, Some(1)).unwrap();
        match state {
            "CLAIMED" => {
                conn.execute("UPDATE provider_credential_operations SET state = 'CLAIMED', continuation_binding_digest = ?1, process_release_binding_digest = ?2, updated_at = updated_at + 1 WHERE operation_id = ?3", rusqlite::params![[1_u8; 32], [2_u8; 32], [101_u8; 16]])
                    .unwrap();
            }
            "NATIVE_EFFECT_OBSERVED" => {
                conn.execute("UPDATE provider_credential_operations SET state = 'CLAIMED', continuation_binding_digest = ?1, process_release_binding_digest = ?2, updated_at = updated_at + 1 WHERE operation_id = ?3", rusqlite::params![[1_u8; 32], [2_u8; 32], [101_u8; 16]]).unwrap();
                conn.execute("UPDATE provider_credential_operations SET state = 'NATIVE_EFFECT_OBSERVED', native_effect_disposition = 'observed', updated_at = updated_at + 1 WHERE operation_id = ?1", [[101_u8; 16]]).unwrap();
            }
            _ => {}
        }
        assert!(conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, active_credential_version = 1, active_ref_digest = ?1 WHERE provider_id = 'pair-state'", [[101_u8; 32]]).is_err(), "premature {state} activation must fail");
    }
}

#[test]
fn cleanup_operation_cannot_substitute_for_pair_activation() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "cleanup-substitution");
    conn.execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, 'cleanup-substitution', 'LEGACY_SOURCE_CLEANUP', ?1, 'cleanup-substitution', 1, 1, 1, ?2, 'PREPARED', ?3, 1, 1)", rusqlite::params![[102_u8; 16], [102_u8; 32], [103_u8; 32]]).unwrap();
    readback_verified_operation(&conn, 102);
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, active_credential_version = 1, active_ref_digest = ?1 WHERE provider_id = 'cleanup-substitution'", [[102_u8; 32]]).is_err());
}

#[test]
fn pair_readback_and_completed_migrate_barrier_are_the_only_activation_paths() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "pair-green");
    insert_allocated_operation(&conn, 104, "pair-green", 1, 1, Some(1)).unwrap();
    readback_verified_operation(&conn, 104);
    conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, active_credential_version = 1, active_ref_digest = ?1 WHERE provider_id = 'pair-green'", [[104_u8; 32]]).unwrap();

    let conn = v24_connection();
    insert_head_for_test(&conn, "migrate-green");
    conn.execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, 'migrate-green', 'MIGRATE_LEGACY', ?1, 'migrate-green', 1, 1, 1, ?2, 'PREPARED', ?3, 1, 1)", rusqlite::params![[105_u8; 16], [105_u8; 32], [106_u8; 32]]).unwrap();
    terminal_operation(&conn, 105);
    conn.execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, 'migrate-green', 'LEGACY_SOURCE_CLEANUP', ?1, 'migrate-cleanup', 1, 1, 2, ?2, 'PREPARED', ?3, 1, 1)", rusqlite::params![[107_u8; 16], [107_u8; 32], [108_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, next_credential_version = 3, active_credential_version = 1, active_ref_digest = ?1, legacy_import_consumed = 1, legacy_source_binding_digest = ?2, legacy_consumed_lifecycle_revision = 2, legacy_cleanup_operation_id = ?3 WHERE provider_id = 'migrate-green'", rusqlite::params![[105_u8; 32], [109_u8; 32], [107_u8; 16]]).unwrap();
}
