#[test]
fn operation_transition_write_once_fields_and_prepared_failure_are_guarded() {
    let conn = v24_connection();
    insert_operation(&conn, 30).unwrap();

    conn.execute(
        "UPDATE provider_credential_operations SET state = 'FAILED', terminal_disposition = 'failed', updated_at = updated_at + 1 WHERE operation_id = ?1",
        [[30_u8; 16]],
    )
    .unwrap();
    assert!(conn
        .execute(
            "UPDATE provider_credential_operations SET terminal_disposition = 'rewritten' WHERE operation_id = ?1",
            [[30_u8; 16]],
        )
        .is_err());

    insert_operation(&conn, 31).unwrap();
    assert!(conn
        .execute(
            "UPDATE provider_credential_operations SET continuation_binding_digest = ?1 WHERE operation_id = ?2",
            rusqlite::params![[9_u8; 32], [31_u8; 16]],
        )
        .is_err());
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'CLAIMED', continuation_binding_digest = ?1, process_release_binding_digest = ?2, updated_at = updated_at + 1 WHERE operation_id = ?3",
        rusqlite::params![[1_u8; 32], [2_u8; 32], [31_u8; 16]],
    )
    .unwrap();
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'NATIVE_EFFECT_OBSERVED', native_effect_disposition = 'observed', updated_at = updated_at + 1 WHERE operation_id = ?1",
        [[31_u8; 16]],
    )
    .unwrap();
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'READBACK_VERIFIED', readback_observation_digest = ?1, updated_at = updated_at + 1 WHERE operation_id = ?2",
        rusqlite::params![[3_u8; 32], [31_u8; 16]],
    )
    .unwrap();
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'COMPLETED', terminal_disposition = 'completed', updated_at = updated_at + 1 WHERE operation_id = ?1",
        [[31_u8; 16]],
    )
    .unwrap();
    for (column, value) in [
        ("continuation_binding_digest", vec![4_u8; 32]),
        ("process_release_binding_digest", vec![5_u8; 32]),
        ("readback_observation_digest", vec![6_u8; 32]),
    ] {
        assert!(conn
            .execute(
                &format!("UPDATE provider_credential_operations SET {column} = ?1 WHERE operation_id = ?2"),
                rusqlite::params![value, [31_u8; 16]],
            )
            .is_err());
    }
    assert!(conn
        .execute(
            "UPDATE provider_credential_operations SET native_effect_disposition = 'rewritten' WHERE operation_id = ?1",
            [[31_u8; 16]],
        )
        .is_err());
    assert!(conn
        .execute(
            "UPDATE provider_credential_operations SET terminal_disposition = 'rewritten' WHERE operation_id = ?1",
            [[31_u8; 16]],
        )
        .is_err());
}

#[test]
fn operation_transitions_require_owned_evidence_at_each_boundary() {
    let conn = v24_connection();
    insert_operation(&conn, 40).unwrap();
    assert!(
        conn.execute(
            "UPDATE provider_credential_operations SET state = 'CLAIMED' WHERE operation_id = ?1",
            [[40_u8; 16]],
        )
        .is_err()
    );
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'FAILED', terminal_disposition = 'missing-claim', updated_at = updated_at + 1 WHERE operation_id = ?1",
        [[40_u8; 16]],
    )
    .unwrap();

    insert_operation(&conn, 41).unwrap();
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'CLAIMED', continuation_binding_digest = ?1, process_release_binding_digest = ?2, updated_at = updated_at + 1 WHERE operation_id = ?3",
        rusqlite::params![[1_u8; 32], [2_u8; 32], [41_u8; 16]],
    )
    .unwrap();
    assert!(conn
        .execute(
            "UPDATE provider_credential_operations SET state = 'NATIVE_EFFECT_OBSERVED' WHERE operation_id = ?1",
            [[41_u8; 16]],
        )
        .is_err());
    assert!(conn.execute("UPDATE provider_credential_operations SET state = 'FAILED', terminal_disposition = 'missing-native', updated_at = updated_at + 1 WHERE operation_id = ?1", [[41_u8; 16]]).is_err());
    conn.execute("UPDATE provider_credential_operations SET state = 'FAILED', readback_observation_digest = ?1, terminal_disposition = 'missing-native', updated_at = updated_at + 1 WHERE operation_id = ?2", rusqlite::params![[41_u8; 32], [41_u8; 16]]).unwrap();
    assert!(conn.execute("UPDATE provider_credential_operations SET readback_observation_digest = ?1 WHERE operation_id = ?2", rusqlite::params![[42_u8; 32], [41_u8; 16]]).is_err());

    insert_operation(&conn, 42).unwrap();
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'CLAIMED', continuation_binding_digest = ?1, process_release_binding_digest = ?2, updated_at = updated_at + 1 WHERE operation_id = ?3",
        rusqlite::params![[3_u8; 32], [4_u8; 32], [42_u8; 16]],
    )
    .unwrap();
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'NATIVE_EFFECT_OBSERVED', native_effect_disposition = 'observed', updated_at = updated_at + 1 WHERE operation_id = ?1",
        [[42_u8; 16]],
    )
    .unwrap();
    assert!(conn
        .execute(
            "UPDATE provider_credential_operations SET state = 'READBACK_VERIFIED' WHERE operation_id = ?1",
            [[42_u8; 16]],
        )
        .is_err());
    assert!(conn.execute("UPDATE provider_credential_operations SET state = 'FAILED', terminal_disposition = 'missing-readback', updated_at = updated_at + 1 WHERE operation_id = ?1", [[42_u8; 16]]).is_err());
    conn.execute("UPDATE provider_credential_operations SET state = 'FAILED', readback_observation_digest = ?1, terminal_disposition = 'missing-readback', updated_at = updated_at + 1 WHERE operation_id = ?2", rusqlite::params![[42_u8; 32], [42_u8; 16]]).unwrap();

    insert_operation(&conn, 44).unwrap();
    assert!(
        conn.execute(
            "UPDATE provider_credential_operations SET state = 'FAILED' WHERE operation_id = ?1",
            [[44_u8; 16]],
        )
        .is_err()
    );
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'FAILED', terminal_disposition = 'failed', updated_at = updated_at + 1 WHERE operation_id = ?1",
        [[44_u8; 16]],
    )
    .unwrap();

    insert_operation(&conn, 43).unwrap();
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'CLAIMED', continuation_binding_digest = ?1, process_release_binding_digest = ?2, updated_at = updated_at + 1 WHERE operation_id = ?3",
        rusqlite::params![[5_u8; 32], [6_u8; 32], [43_u8; 16]],
    )
    .unwrap();
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'NATIVE_EFFECT_OBSERVED', native_effect_disposition = 'observed', updated_at = updated_at + 1 WHERE operation_id = ?1",
        [[43_u8; 16]],
    )
    .unwrap();
    conn.execute(
        "UPDATE provider_credential_operations SET state = 'READBACK_VERIFIED', readback_observation_digest = ?1, updated_at = updated_at + 1 WHERE operation_id = ?2",
        rusqlite::params![[7_u8; 32], [43_u8; 16]],
    )
    .unwrap();
    assert!(
        conn.execute(
            "UPDATE provider_credential_operations SET state = 'COMPLETED' WHERE operation_id = ?1",
            [[43_u8; 16]],
        )
        .is_err()
    );
}

#[test]
fn migration_operations_require_matching_action_phase() {
    let conn = v24_connection();
    let insert = "INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, migration_id, migration_phase, migration_old_tuple_digest, migration_new_tuple_digest, created_at, updated_at) VALUES (?1, 'provider', ?2, ?1, ?3, 1, 1, 'PREPARED', ?4, ?5, ?6, ?7, ?8, 1, 1)";
    assert!(
        conn.execute(
            insert,
            rusqlite::params![
                [32_u8; 16],
                "WRITER_IDENTITY_MIGRATION_EFFECT",
                "cross-effect",
                [32_u8; 32],
                [33_u8; 16],
                "VERIFY",
                [34_u8; 32],
                [35_u8; 32]
            ],
        )
        .is_err()
    );
    assert!(
        conn.execute(
            insert,
            rusqlite::params![
                [36_u8; 16],
                "WRITER_IDENTITY_MIGRATION_VERIFY",
                "cross-verify",
                [36_u8; 32],
                [37_u8; 16],
                "EFFECT",
                [38_u8; 32],
                [39_u8; 32]
            ],
        )
        .is_err()
    );
}

#[test]
fn v24_insert_guards_require_authoritative_heads_and_default_state() {
    let conn = v24_connection();
    assert!(conn
        .execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, 'missing-head', 'PAIR', ?1, 'missing-head', 1, 1, 1, ?2, 'PREPARED', ?3, 1, 1)", rusqlite::params![[50_u8; 16], [51_u8; 32], [52_u8; 32]])
        .is_err());
    assert!(conn
        .execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version, active_credential_version, active_ref_digest) VALUES ('active-on-insert', 1, 1, 1, 1, 1, ?1)", [[53_u8; 32]])
        .is_err());
    assert!(conn
        .execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version, hard_fence_disposition, hard_fence_diagnostic_digest) VALUES ('fenced-on-insert', 1, 1, 1, 1, 'INVARIANT_FAILURE', ?1)", [[54_u8; 32]])
        .is_err());
}

#[test]
fn provider_ids_are_canonical_ascii_graphic_and_bounded() {
    let conn = v24_connection();
    let operation = "INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, ?2, 'PAIR', ?1, ?3, 1, 1, 'PREPARED', ?4, 1, 1)";
    for (value, id) in [
        ("bad\nprovider", 56_u8),
        ("é", 57_u8),
        (&"x".repeat(129), 58_u8),
    ] {
        assert!(
            conn.execute(
                operation,
                rusqlite::params![[id; 16], value, format!("provider-{id}"), [id; 32]],
            )
            .is_err()
        );
    }
    for (value, id) in [
        ("bad\t-head", 59_u8),
        ("é", 60_u8),
        (&"h".repeat(129), 61_u8),
    ] {
        assert!(conn
            .execute(
                "INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES (?1, 1, 1, 1, 1)",
                rusqlite::params![value],
            )
            .is_err(),
            "invalid provider id case {id} must fail",
        );
    }
}

#[test]
fn active_credential_version_is_positive_and_below_next_version() {
    let conn = v24_connection();
    conn.execute(
        "INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES ('active-check', 1, 1, 1, 1)",
        [],
    )
    .unwrap();
    for value in [0_i64, -1_i64, 1_i64] {
        assert!(conn
            .execute(
                "UPDATE provider_credential_authority_heads SET active_credential_version = ?1, active_ref_digest = ?2 WHERE provider_id = 'active-check'",
                rusqlite::params![value, [62_u8; 32]],
            )
            .is_err());
    }
    insert_allocated_operation(&conn, 64, "active-check", 1, 1, Some(1)).unwrap();
    readback_verified_operation(&conn, 64);
    conn.execute(
        "UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, active_credential_version = 1, active_ref_digest = ?1 WHERE provider_id = 'active-check'",
        [[64_u8; 32]],
    )
    .unwrap();
}

#[test]
fn operation_created_at_is_immutable() {
    let conn = v24_connection();
    insert_operation(&conn, 55).unwrap();
    assert!(
        conn.execute(
            "UPDATE provider_credential_operations SET created_at = 2 WHERE operation_id = ?1",
            [[55_u8; 16]],
        )
        .is_err()
    );
}
