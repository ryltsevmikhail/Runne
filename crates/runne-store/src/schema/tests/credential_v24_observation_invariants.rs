#[test]
fn verification_observations_have_one_use_lease_and_completion() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "verify");
    conn.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water = 1 WHERE provider_id = 'verify'", []).unwrap();
    let insert = "INSERT INTO provider_credential_verification_observations (observation_id, provider_id, verification_kind, lifecycle_revision, credential_fence, state, result, intent_proof_digest, proof_consumed, verifier_revision, started_at, expires_at_high_water, observed_at, operation_id) VALUES (?1, ?2, ?3, ?4, ?5, 'LEASED', ?6, ?7, ?8, ?9, 1, 3, ?10, NULL)";
    assert!(
        conn.execute(
            insert,
            rusqlite::params![
                [30_u8; 16],
                "verify",
                "LOCAL",
                1,
                1,
                Some("VERIFIED"),
                [30_u8; 32],
                1,
                7,
                Option::<i64>::None
            ]
        )
        .is_err()
    );
    assert!(conn.execute("INSERT INTO provider_credential_verification_observations (observation_id, provider_id, verification_kind, lifecycle_revision, credential_fence, state, result, intent_proof_digest, proof_consumed, verifier_revision, started_at, expires_at_high_water, observed_at) VALUES (?1, 'verify', 'LOCAL', 1, 1, 'LEASED', NULL, ?2, 1, 7, 1, 3, NULL)", rusqlite::params![[31_u8; 16], [31_u8; 32]]).is_ok());
    conn.execute("UPDATE provider_credential_verification_observations SET state = 'COMPLETED', result = 'VERIFIED', observed_at = 1 WHERE observation_id = ?1", [[31_u8; 16]]).unwrap();
    assert!(
        conn.execute(
            "UPDATE provider_credential_verification_observations SET result = 'FAILED' WHERE observation_id = ?1",
            [[31_u8; 16]]
        )
        .is_err()
    );
    conn.execute("INSERT INTO provider_credential_verification_observations (observation_id, provider_id, verification_kind, lifecycle_revision, credential_fence, state, result, intent_proof_digest, proof_consumed, verifier_revision, started_at, expires_at_high_water, observed_at) VALUES (?1, 'verify', 'LOCAL', 1, 1, 'LEASED', NULL, ?2, 1, 8, 1, 3, NULL)", rusqlite::params![[32_u8; 16], [32_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, observed_at_high_water = 2 WHERE provider_id = 'verify'", []).unwrap();
    assert!(
        conn.execute(
            "UPDATE provider_credential_verification_observations SET state = 'COMPLETED', result = 'VERIFIED', observed_at = 2 WHERE observation_id = ?1",
            [[32_u8; 16]]
        )
        .is_err()
    );
}

#[test]
fn verification_remote_requires_completed_local_and_exact_fence() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "verify-remote");
    conn.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water = 1 WHERE provider_id = 'verify-remote'", []).unwrap();
    let insert = "INSERT INTO provider_credential_verification_observations (observation_id, provider_id, verification_kind, lifecycle_revision, credential_fence, state, result, intent_proof_digest, proof_consumed, verifier_revision, started_at, expires_at_high_water, observed_at) VALUES (?1, 'verify-remote', ?2, 1, ?3, 'LEASED', NULL, ?4, ?5, ?6, ?7, ?8, NULL)";
    assert!(
        conn.execute(
            insert,
            rusqlite::params![[40_u8; 16], "REMOTE", 1, [40_u8; 32], 0, 7, 1, 3]
        )
        .is_err()
    );
    conn.execute(
        insert,
        rusqlite::params![[41_u8; 16], "LOCAL", 1, [41_u8; 32], 1, 7, 1, 3],
    )
    .unwrap();
    conn.execute("UPDATE provider_credential_verification_observations SET state = 'COMPLETED', result = 'VERIFIED', observed_at = 1 WHERE observation_id = ?1", [[41_u8; 16]]).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water = 2 WHERE provider_id = 'verify-remote'", []).unwrap();
    conn.execute(
        insert,
        rusqlite::params![[42_u8; 16], "REMOTE", 1, [42_u8; 32], 1, 7, 2, 4],
    )
    .unwrap();
    conn.execute("UPDATE provider_credential_verification_observations SET state = 'COMPLETED', result = 'VERIFIED', observed_at = 2 WHERE observation_id = ?1", [[42_u8; 16]]).unwrap();
    assert!(
        conn.execute(
            insert,
            rusqlite::params![[43_u8; 16], "LOCAL", 2, [43_u8; 32], 1, 7, 2, 4]
        )
        .is_err()
    );
}

#[test]
fn verification_lease_operation_is_provider_owned() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "verify-owned");
    insert_head_for_test(&conn, "verify-other");
    insert_observation_operation(&conn, 50, "verify-owned");
    insert_observation_operation(&conn, 51, "verify-other");
    conn.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water = 1 WHERE provider_id = 'verify-owned'", []).unwrap();
    let insert = "INSERT INTO provider_credential_verification_observations (observation_id, provider_id, verification_kind, lifecycle_revision, credential_fence, state, result, intent_proof_digest, proof_consumed, verifier_revision, started_at, expires_at_high_water, observed_at, operation_id) VALUES (?1, 'verify-owned', 'LOCAL', 1, 1, 'LEASED', NULL, ?2, 1, 7, 1, 3, NULL, ?3)";
    conn.execute(
        insert,
        rusqlite::params![[52_u8; 16], [52_u8; 32], [50_u8; 16]],
    )
    .unwrap();
    assert!(
        conn.execute(
            insert,
            rusqlite::params![[53_u8; 16], [53_u8; 32], [51_u8; 16]]
        )
        .is_err()
    );
}

#[test]
fn readiness_records_fence_and_release_failures_but_never_ready() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "fenced-ready");
    conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, hard_fence_disposition = 'INVARIANT_FAILURE', hard_fence_diagnostic_digest = ?1 WHERE provider_id = 'fenced-ready'", [[40_u8; 32]]).unwrap();
    let insert = "INSERT INTO provider_credential_readiness_observations (observation_id, provider_id, lifecycle_revision, readiness_revision, disposition, active_binding_digest, release_tuple_digest, observed_at, operation_id) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, 1, NULL)";
    conn.execute(
        insert,
        rusqlite::params![
            [41_u8; 16],
            "fenced-ready",
            2,
            2,
            "INVARIANT_FAILURE",
            [41_u8; 32]
        ],
    )
    .unwrap();
    assert!(conn.execute("INSERT INTO provider_credential_readiness_observations (observation_id, provider_id, lifecycle_revision, readiness_revision, disposition, active_binding_digest, release_tuple_digest, observed_at) VALUES (?1, 'fenced-ready', 2, 2, 'READY', ?2, ?3, 2)", rusqlite::params![[42_u8; 16], [42_u8; 32], [42_u8; 32]]).is_err());

    insert_head_for_test(&conn, "pending-ready");
    conn.execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, migration_id, migration_phase, migration_old_tuple_digest, migration_new_tuple_digest, created_at, updated_at) VALUES (?1, 'pending-ready', 'WRITER_IDENTITY_MIGRATION_VERIFY', ?1, 'pending-ready', 1, 1, 'PREPARED', ?2, ?3, 'VERIFY', ?4, ?5, 1, 1)", rusqlite::params![[43_u8; 16], [43_u8; 32], [43_u8; 16], [44_u8; 32], [45_u8; 32]]).unwrap();
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET release_migration_fence = 1, release_migration_binding_digest = ?1, release_migration_operation_id = ?2, release_migration_state = 'PENDING', readiness_revision = 2 WHERE provider_id = 'pending-ready'", rusqlite::params![[45_u8; 32], [43_u8; 16]]).is_err());
    conn.execute("UPDATE provider_credential_authority_heads SET release_migration_fence = 1, release_migration_binding_digest = ?1, release_migration_operation_id = ?2, release_migration_state = 'PENDING', readiness_revision = 2, credential_fence = 2 WHERE provider_id = 'pending-ready'", rusqlite::params![[45_u8; 32], [43_u8; 16]]).unwrap();
    conn.execute(
        insert,
        rusqlite::params![
            [46_u8; 16],
            "pending-ready",
            1,
            2,
            "UNAVAILABLE",
            [46_u8; 32]
        ],
    )
    .unwrap();
    assert!(conn.execute("INSERT INTO provider_credential_readiness_observations (observation_id, provider_id, lifecycle_revision, readiness_revision, disposition, active_binding_digest, release_tuple_digest, observed_at) VALUES (?1, 'pending-ready', 1, 2, 'READY', ?2, ?3, 2)", rusqlite::params![[47_u8; 16], [47_u8; 32], [47_u8; 32]]).is_err());
}

#[test]
fn credential_and_release_mutations_invalidate_old_verification_and_ready_state() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "rotate");
    conn.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water = 1 WHERE provider_id = 'rotate'", []).unwrap();
    insert_allocated_operation(&conn, 80, "rotate", 1, 1, Some(1)).unwrap();
    readback_verified_operation(&conn, 80);
    conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, active_credential_version = 1, active_ref_digest = ?1 WHERE provider_id = 'rotate'", [[80_u8; 32]]).unwrap();
    conn.execute("INSERT INTO provider_credential_readiness_observations (observation_id, provider_id, lifecycle_revision, readiness_revision, disposition, active_binding_digest, release_tuple_digest, observed_at) VALUES (?1, 'rotate', 2, 2, 'READY', ?2, ?3, 1)", rusqlite::params![[81_u8; 16], [80_u8; 32], [81_u8; 32]]).unwrap();
    conn.execute("INSERT INTO provider_credential_verification_observations (observation_id, provider_id, verification_kind, lifecycle_revision, credential_fence, state, result, intent_proof_digest, proof_consumed, verifier_revision, started_at, expires_at_high_water, observed_at) VALUES (?1, 'rotate', 'LOCAL', 2, 2, 'LEASED', NULL, ?2, 1, 7, 1, 3, NULL)", rusqlite::params![[82_u8; 16], [82_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_operations SET state = 'COMPLETED', terminal_disposition = 'completed', updated_at = updated_at + 1 WHERE operation_id = ?1", [[80_u8; 16]]).unwrap();
    conn.execute("INSERT INTO provider_credential_operations (operation_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, migration_id, migration_phase, migration_old_tuple_digest, migration_new_tuple_digest, created_at, updated_at) VALUES (?1, 'rotate', 'WRITER_IDENTITY_MIGRATION_VERIFY', ?1, 'rotate-release', 2, 2, 'PREPARED', ?2, ?3, 'VERIFY', ?4, ?5, 1, 1)", rusqlite::params![[83_u8; 16], [83_u8; 32], [84_u8; 16], [85_u8; 32], [86_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET credential_fence = 3, readiness_revision = 3, release_migration_fence = 1, release_migration_binding_digest = ?1, release_migration_operation_id = ?2, release_migration_state = 'PENDING' WHERE provider_id = 'rotate'", rusqlite::params![[86_u8; 32], [83_u8; 16]]).unwrap();
    terminal_operation(&conn, 83);
    conn.execute("UPDATE provider_credential_authority_heads SET readiness_revision = 4, release_migration_state = 'VERIFIED' WHERE provider_id = 'rotate'", []).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET readiness_revision = 5, release_migration_state = 'CLEARED' WHERE provider_id = 'rotate'", []).unwrap();
    assert!(conn.execute("UPDATE provider_credential_verification_observations SET state = 'COMPLETED', result = 'VERIFIED', observed_at = 1 WHERE observation_id = ?1", [[82_u8; 16]]).is_err());
    assert!(conn.execute("INSERT INTO provider_credential_readiness_observations (observation_id, provider_id, lifecycle_revision, readiness_revision, disposition, active_binding_digest, release_tuple_digest, observed_at) VALUES (?1, 'rotate', 2, 2, 'READY', ?2, ?3, 1)", rusqlite::params![[87_u8; 16], [80_u8; 32], [87_u8; 32]]).is_err());
}

#[test]
fn verification_completion_obeys_store_high_water_and_expiry_boundary() {
    let conn = v24_connection();
    insert_head_for_test(&conn, "expiry");
    conn.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water = 1 WHERE provider_id = 'expiry'", []).unwrap();
    assert!(conn.execute("INSERT INTO provider_credential_verification_observations (observation_id, provider_id, verification_kind, lifecycle_revision, credential_fence, state, result, intent_proof_digest, proof_consumed, verifier_revision, started_at, expires_at_high_water, observed_at) VALUES (?1, 'expiry', 'LOCAL', 1, 1, 'LEASED', NULL, ?2, 1, 7, 1, 1, NULL)", rusqlite::params![[88_u8; 16], [88_u8; 32]]).is_err());
    conn.execute("INSERT INTO provider_credential_verification_observations (observation_id, provider_id, verification_kind, lifecycle_revision, credential_fence, state, result, intent_proof_digest, proof_consumed, verifier_revision, started_at, expires_at_high_water, observed_at) VALUES (?1, 'expiry', 'LOCAL', 1, 1, 'LEASED', NULL, ?2, 1, 7, 1, 3, NULL)", rusqlite::params![[89_u8; 16], [89_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water = 2 WHERE provider_id = 'expiry'", []).unwrap();
    assert!(conn.execute("UPDATE provider_credential_verification_observations SET state = 'COMPLETED', result = 'VERIFIED', observed_at = 1 WHERE observation_id = ?1", [[89_u8; 16]]).is_err());
    conn.execute("UPDATE provider_credential_verification_observations SET state = 'COMPLETED', result = 'VERIFIED', observed_at = 2 WHERE observation_id = ?1", [[89_u8; 16]]).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water = 3 WHERE provider_id = 'expiry'", []).unwrap();
    assert!(conn.execute("INSERT INTO provider_credential_verification_observations (observation_id, provider_id, verification_kind, lifecycle_revision, credential_fence, state, result, intent_proof_digest, proof_consumed, verifier_revision, started_at, expires_at_high_water, observed_at) VALUES (?1, 'expiry', 'LOCAL', 1, 1, 'LEASED', NULL, ?2, 1, 7, 3, 4, NULL)", rusqlite::params![[90_u8; 16], [90_u8; 32]]).is_ok());
    conn.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water = 4 WHERE provider_id = 'expiry'", []).unwrap();
    assert!(conn.execute("UPDATE provider_credential_verification_observations SET state = 'COMPLETED', result = 'VERIFIED', observed_at = 4 WHERE observation_id = ?1", [[90_u8; 16]]).is_err());
}

#[test]
fn leased_verification_survives_reopen_with_its_expiry_guard() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lease.sqlite");
    let conn = Connection::open(&path).unwrap();
    initialize_released_v23(&conn);
    apply_migrations(&conn).unwrap();
    insert_head_for_test(&conn, "restart-expiry");
    conn.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water = 1 WHERE provider_id = 'restart-expiry'", []).unwrap();
    drop(conn);
    let conn = Connection::open(&path).unwrap();
    assert!(v24_matches(&conn, 24).unwrap());
    conn.execute("INSERT INTO provider_credential_verification_observations (observation_id, provider_id, verification_kind, lifecycle_revision, credential_fence, state, result, intent_proof_digest, proof_consumed, verifier_revision, started_at, expires_at_high_water, observed_at) VALUES (?1, 'restart-expiry', 'LOCAL', 1, 1, 'LEASED', NULL, ?2, 1, 7, 1, 3, NULL)", rusqlite::params![[98_u8; 16], [98_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water = 2 WHERE provider_id = 'restart-expiry'", []).unwrap();
    conn.execute("UPDATE provider_credential_verification_observations SET state = 'COMPLETED', result = 'VERIFIED', observed_at = 2 WHERE observation_id = ?1", [[98_u8; 16]]).unwrap();
}

#[test]
fn every_v24_enforcement_trigger_is_required_by_catalog() {
    for (name, _) in V24_TRIGGERS {
        let conn = v24_connection();
        conn.execute_batch(&format!("DROP TRIGGER {name}")).unwrap();
        assert!(
            !v24_matches(&conn, 24).unwrap(),
            "missing trigger {name} must fail catalog validation"
        );
    }
}

#[test]
fn every_v24_table_and_index_is_required_by_catalog() {
    for table in [
        "provider_credential_operations",
        "provider_credential_ticket_attempts",
        "provider_credential_authority_heads",
        "provider_credential_readiness_observations",
        "provider_credential_verification_observations",
    ] {
        let conn = v24_connection();
        conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        conn.execute_batch(&format!("DROP TABLE {table}")).unwrap();
        assert!(
            !v24_matches(&conn, 24).unwrap(),
            "missing table {table} must fail catalog validation"
        );
    }
    let conn = v24_connection();
    conn.execute_batch("DROP INDEX provider_credential_one_non_terminal_operation")
        .unwrap();
    assert!(
        !v24_matches(&conn, 24).unwrap(),
        "missing V24 partial index must fail catalog validation"
    );
}
