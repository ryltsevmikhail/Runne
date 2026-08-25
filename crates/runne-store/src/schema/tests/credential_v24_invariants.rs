fn insert_head_for_test(conn: &Connection, provider: &str) {
    conn.execute(
        "INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES (?1, 1, 1, 1, 1)",
        [provider],
    )
    .unwrap();
}

fn insert_observation_operation(conn: &Connection, value: u8, provider: &str) {
    conn.execute(
        "INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, ?2, 'PAIR', ?1, ?3, 1, 1, 'PREPARED', ?4, 1, 1)",
        rusqlite::params![[value; 16], provider, format!("obs-{value}"), [value; 32]],
    )
    .unwrap();
}

fn insert_allocated_operation(
    conn: &Connection,
    id: u8,
    provider: &str,
    revision: i64,
    fence: i64,
    version: Option<i64>,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, ?2, 'PAIR', ?1, ?3, ?4, ?5, ?6, ?7, 'PREPARED', ?8, 1, 1)",
        rusqlite::params![[id; 16], provider, format!("alloc-{id}"), revision, fence, version, version.map(|_| vec![id; 32]), [id; 32]],
    )
}

fn readback_verified_operation(conn: &Connection, value: u8) {
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'CLAIMED', continuation_binding_digest = ?1, process_release_binding_digest = ?2, updated_at = updated_at + 1 WHERE operation_id = ?3",
        rusqlite::params![[value; 32], [value.wrapping_add(1); 32], [value; 16]],
    )
    .unwrap();
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'NATIVE_EFFECT_OBSERVED', native_effect_disposition = 'observed', updated_at = updated_at + 1 WHERE operation_id = ?1",
        [[value; 16]],
    )
    .unwrap();
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'READBACK_VERIFIED', readback_observation_digest = ?1, updated_at = updated_at + 1 WHERE operation_id = ?2",
        rusqlite::params![[value.wrapping_add(2); 32], [value; 16]],
    )
    .unwrap();
}

#[test]
fn operation_insert_requires_current_head_and_allocations_are_consumed() {
    let conn = v24_connection();
    assert!(insert_allocated_operation(&conn, 1, "missing", 1, 1, None).is_err());
    insert_head_for_test(&conn, "alloc");
    conn.execute(
        "UPDATE provider_credential_authority_heads SET hard_fence_disposition = 'INVARIANT_FAILURE', hard_fence_diagnostic_digest = ?1, lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2 WHERE provider_id = 'alloc'",
        [[2_u8; 32]],
    )
    .unwrap();
    assert!(insert_allocated_operation(&conn, 2, "alloc", 1, 1, None).is_err());
    assert!(insert_allocated_operation(&conn, 3, "alloc", 2, 2, None).is_err());

    let conn = v24_connection();
    insert_head_for_test(&conn, "alloc");
    insert_allocated_operation(&conn, 4, "alloc", 1, 1, Some(1)).unwrap();
    assert_eq!(
        conn.query_row("SELECT next_credential_version FROM provider_credential_authority_heads WHERE provider_id = 'alloc'", [], |row| row.get::<_, i64>(0)).unwrap(),
        2
    );
    assert!(insert_allocated_operation(&conn, 5, "alloc", 1, 1, Some(1)).is_err());
    terminal_operation(&conn, 4);
    insert_allocated_operation(&conn, 6, "alloc", 1, 1, Some(2)).unwrap();
}

#[test]
fn strict_v24_tables_reject_storage_class_confusion() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "typed");
    let operation = "INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, ?2, 'PAIR', ?1, ?3, ?4, 1, 'PREPARED', ?5, 1, 1)";
    assert!(
        conn.execute(
            operation,
            rusqlite::params![
                [10_u8; 16],
                rusqlite::types::Value::Blob(b"typed".to_vec()),
                "typed-b",
                [10_u8; 32],
                [10_u8; 32]
            ]
        )
        .is_err()
    );
    assert!(
        conn.execute(
            operation,
            rusqlite::params![[11_u8; 16], "typed", "typed-r", 1.5_f64, [11_u8; 32]]
        )
        .is_err()
    );
    assert!(
        conn.execute(
            operation,
            rusqlite::params![[12_u8; 16], "typed", "typed-d", 1_i64, "not-a-blob"]
        )
        .is_err()
    );
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET credential_fence = ?1 WHERE provider_id = 'typed'", [1.5_f64]).is_err());
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = ?1 WHERE provider_id = 'typed'", [1.5_f64]).is_err());
    insert_observation_operation(&conn, 13, "typed");
    assert!(conn.execute("INSERT INTO provider_credential_ticket_attempts (operation_id, attempt, ticket_digest, continuation_binding_digest, issued_at, expires_at, state) VALUES (?1, ?2, ?3, ?4, ?5, 3, 'ISSUED')", rusqlite::params![[13_u8; 16], 1.5_f64, [13_u8; 32], [14_u8; 32], 1_i64]).is_err());
    assert!(conn.execute("INSERT INTO provider_credential_ticket_attempts (operation_id, attempt, ticket_digest, continuation_binding_digest, issued_at, expires_at, state) VALUES (?1, 1, ?2, ?3, ?4, 3, 'ISSUED')", rusqlite::params![[13_u8; 16], "text-digest", [14_u8; 32], 1.5_f64]).is_err());
}

#[test]
fn provider_ids_reject_embedded_and_leading_nul_bytes() {
    for (id, provider) in [(60_u8, "a\0b"), (61_u8, "\0ab")] {
        let conn = v24_connection();
        assert!(conn.execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES (?1, 1, 1, 1, 1)", [provider]).is_err());
        conn.execute_batch("DROP TRIGGER provider_credential_operation_insert_prepared")
            .unwrap();
        assert!(conn.execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, ?2, 'PAIR', ?1, ?3, 1, 1, 'PREPARED', ?4, 1, 1)", rusqlite::params![[id; 16], provider, format!("nul-{id}"), [id; 32]]).is_err());
    }
}

#[test]
fn legacy_cutover_rejects_preexisting_active_and_requires_revision_boundary() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "legacy-boundary");
    insert_allocated_operation(&conn, 71, "legacy-boundary", 1, 1, Some(1)).unwrap();
    readback_verified_operation(&conn, 71);
    conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, active_credential_version = 1, active_ref_digest = ?1 WHERE provider_id = 'legacy-boundary'", [[71_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_operations SET state = 'COMPLETED', terminal_disposition = 'completed', updated_at = updated_at + 1 WHERE operation_id = ?1", [[71_u8; 16]]).unwrap();
    conn.execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, 'legacy-boundary', 'LEGACY_SOURCE_CLEANUP', ?1, 'legacy-boundary-cleanup', 2, 2, 2, ?2, 'PREPARED', ?3, 1, 1)", rusqlite::params![[72_u8; 16], [72_u8; 32], [73_u8; 32]]).unwrap();
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET legacy_import_consumed = 1, legacy_source_binding_digest = ?1, legacy_consumed_lifecycle_revision = 2, lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, legacy_cleanup_operation_id = ?2 WHERE provider_id = 'legacy-boundary'", rusqlite::params![[73_u8; 32], [72_u8; 16]]).is_err());
}

#[test]
fn readiness_observations_bind_current_head_and_owned_operations() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "ready-a");
    insert_head_for_test(&conn, "ready-b");
    insert_observation_operation(&conn, 20, "ready-a");
    let insert = "INSERT INTO provider_credential_readiness_observations (observation_id, provider_id, lifecycle_revision, readiness_revision, disposition, active_binding_digest, release_tuple_digest, observed_at, operation_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)";
    assert!(
        conn.execute(
            insert,
            rusqlite::params![
                [21_u8; 16],
                "ready-a",
                2,
                1,
                "MISSING",
                Option::<Vec<u8>>::None,
                [21_u8; 32],
                Option::<Vec<u8>>::None
            ]
        )
        .is_err()
    );
    assert!(
        conn.execute(
            insert,
            rusqlite::params![
                [22_u8; 16],
                "ready-b",
                1,
                1,
                "MISSING",
                Option::<Vec<u8>>::None,
                [22_u8; 32],
                [20_u8; 16]
            ]
        )
        .is_err()
    );
    conn.execute(
        insert,
        rusqlite::params![
            [23_u8; 16],
            "ready-a",
            1,
            1,
            "MISSING",
            Option::<Vec<u8>>::None,
            [23_u8; 32],
            [20_u8; 16]
        ],
    )
    .unwrap();
    terminal_operation(&conn, 20);
    conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2 WHERE provider_id = 'ready-a'", []).unwrap();
    conn.execute(
        insert,
        rusqlite::params![
            [27_u8; 16],
            "ready-a",
            2,
            2,
            "MISSING",
            Option::<Vec<u8>>::None,
            [27_u8; 32],
            [20_u8; 16]
        ],
    )
    .unwrap();

    insert_allocated_operation(&conn, 24, "ready-b", 1, 1, Some(1)).unwrap();
    readback_verified_operation(&conn, 24);
    conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, active_credential_version = 1, active_ref_digest = ?1 WHERE provider_id = 'ready-b'", [[24_u8; 32]]).unwrap();
    assert!(
        conn.execute(
            insert,
            rusqlite::params![
                [25_u8; 16],
                "ready-b",
                2,
                2,
                "READY",
                [25_u8; 32],
                [25_u8; 32],
                Option::<Vec<u8>>::None
            ]
        )
        .is_err()
    );
    conn.execute(
        insert,
        rusqlite::params![
            [26_u8; 16],
            "ready-b",
            2,
            2,
            "READY",
            [24_u8; 32],
            [26_u8; 32],
            Option::<Vec<u8>>::None
        ],
    )
    .unwrap();
}

#[test]
fn active_removal_requires_revoke_or_hard_fence_and_advances_fences() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "revoke");
    insert_allocated_operation(&conn, 78, "revoke", 1, 1, Some(1)).unwrap();
    readback_verified_operation(&conn, 78);
    conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, active_credential_version = 1, active_ref_digest = ?1 WHERE provider_id = 'revoke'", [[78_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_operations SET state = 'COMPLETED', terminal_disposition = 'completed', updated_at = updated_at + 1 WHERE operation_id = ?1", [[78_u8; 16]]).unwrap();
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET active_credential_version = 2, active_ref_digest = ?1, lifecycle_revision = 3, credential_fence = 3, readiness_revision = 3 WHERE provider_id = 'revoke'", [[79_u8; 32]]).is_err());
    insert_allocated_operation(&conn, 79, "revoke", 2, 2, Some(2)).unwrap();
    readback_verified_operation(&conn, 79);
    conn.execute("UPDATE provider_credential_authority_heads SET active_credential_version = 2, active_ref_digest = ?1, lifecycle_revision = 3, credential_fence = 3, readiness_revision = 3 WHERE provider_id = 'revoke'", [[79_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_operations SET state = 'COMPLETED', terminal_disposition = 'completed', updated_at = updated_at + 1 WHERE operation_id = ?1", [[79_u8; 16]]).unwrap();
    conn.execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, 'revoke', 'REVOKE', ?1, 'revoke-op', 3, 3, 'PREPARED', ?2, 1, 1)", rusqlite::params![[80_u8; 16], [80_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET active_credential_version = NULL, active_ref_digest = NULL, lifecycle_revision = 4, credential_fence = 4, readiness_revision = 4 WHERE provider_id = 'revoke'", []).unwrap();
}

#[test]
fn idempotency_keys_are_bounded_utf8_and_control_free() {
    for (id, key, accepted) in [
        (70_u8, "", false),
        (71, "a\0b", false),
        (72, "\0leading", false),
        (73, "line\nfeed", false),
        (74, "delete\u{7f}", false),
        (75, &"a".repeat(257), false),
        (76, &"a".repeat(256), true),
        (77, &"é".repeat(128), true),
    ] {
        let conn = v24_connection();
        conn.execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES ('idempotency', 1, 1, 1, 1)", []).unwrap();
        let result = conn.execute(
            "INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, 'idempotency', 'PAIR', ?1, ?2, 1, 1, 'PREPARED', ?3, 1, 1)",
            rusqlite::params![[id; 16], key, [id; 32]],
        );
        assert_eq!(result.is_ok(), accepted, "idempotency case {id}");
    }
}
