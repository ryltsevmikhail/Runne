// Task 6 status ledger:
// 8 covered: released V8 migration/open is tested below.
// 10 partial: local current preflight is covered externally; the historical
// old-binary portion is blocked because no historical-binary harness exists.
// 11 blocked: rollback with an authority switch is not implemented or qualified.

#[test]
fn v20_rejects_released_v8_fixture_without_a_valid_complete_replay_history() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("released-v8.sqlite");
    let conn = Connection::open(&path).unwrap();
    initialize_released_v8(&conn);
    conn.execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (1, ?1, 1, ?2, 0, 0)",
            params![TEST_ID, [0x24_u8; 16]],
        )
        .unwrap();
    conn.execute(
        "INSERT INTO events
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor,
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile)
             VALUES (?1, 1, ?2, 1, 1, 0, 0, 1, NULL, ?3, x'01', x'02', x'03', ?4, ?2, 1, 1)",
        params![[0x24_u8; 16], TEST_ID, [0x25_u8; 16], [0x26_u8; 32]],
    )
    .unwrap();
    let before: (Vec<u8>, Vec<u8>, i64, Vec<u8>) = conn
        .query_row(
            "SELECT event_id, aggregate_id, global_position, integrity_digest FROM events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    drop(conn);

    preflight_existing_file(&path).unwrap();
    let conn = open_managed_connection(&path, ConnectionMode::Writer).unwrap();

    assert!(apply_migrations(&conn).is_err());

    let after: (Vec<u8>, Vec<u8>, i64, Vec<u8>) = conn
        .query_row(
            "SELECT event_id, aggregate_id, global_position, integrity_digest FROM events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(
        conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        18
    );
}

#[test]
fn corrupt_v24_catalog_is_rejected_before_open() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_released_v23(&conn);
    apply_migrations(&conn).unwrap();
    assert_eq!(CURRENT_SCHEMA_VERSION, 24);
    conn.execute_batch("DROP TABLE provider_credential_operations;")
        .unwrap();
    assert!(classify_existing_connection(&conn).is_err());
}

#[test]
fn v23_to_v24_catalog_reopens_after_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("v23-to-v24.sqlite");
    let conn = Connection::open(&path).unwrap();
    initialize_released_v23(&conn);
    assert_eq!(current_schema_marker(&conn), 23);
    apply_migrations(&conn).unwrap();
    assert_eq!(current_schema_marker(&conn), 24);
    drop(conn);
    let reopened = Connection::open(&path).unwrap();
    assert!(v24_matches(&reopened, 24).unwrap());
}

#[test]
fn interrupted_v24_migration_recovers_from_v23() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_released_v23(&conn);
    let transaction = conn.unchecked_transaction().unwrap();
    transaction.execute_batch(MIGRATION_V24).unwrap();
    assert!(
        transaction
            .execute_batch("CREATE TABLE interrupted_v24 (")
            .is_err()
    );
    transaction.rollback().unwrap();
    assert_eq!(current_schema_marker(&conn), 23);
    assert!(
        conn.execute("SELECT * FROM provider_credential_operations", [])
            .is_err()
    );
    apply_migrations(&conn).unwrap();
    assert_eq!(current_schema_marker(&conn), 24);
}

#[test]
fn one_non_terminal_operation_per_provider() {
    let conn = v24_connection();
    insert_operation(&conn, 1).unwrap();
    assert!(insert_operation(&conn, 2).is_err());
}

#[test]
fn ticket_attempt_digest_is_one_time_and_tombstoned() {
    let conn = v24_connection();
    insert_operation(&conn, 1).unwrap();
    conn.execute("INSERT INTO provider_credential_ticket_attempts (operation_id, attempt, ticket_digest, continuation_binding_digest, issued_at, expires_at, state) VALUES (?1, 1, ?2, ?3, 1, 2, 'ISSUED')", params![[1_u8; 16], [2_u8; 32], [3_u8; 32]]).unwrap();
    assert!(conn.execute("INSERT INTO provider_credential_ticket_attempts (operation_id, attempt, ticket_digest, continuation_binding_digest, issued_at, expires_at, state) VALUES (?1, 2, ?2, ?3, 3, 4, 'ISSUED')", params![[1_u8; 16], [2_u8; 32], [4_u8; 32]]).is_err());
    assert!(conn.execute("INSERT INTO provider_credential_ticket_attempts (operation_id, attempt, ticket_digest, continuation_binding_digest, issued_at, expires_at, state) VALUES (?1, 2, ?2, ?3, 3, 4, 'ISSUED')", params![[1_u8; 16], [6_u8; 32], [7_u8; 32]]).is_err());
    conn.execute(
        "UPDATE provider_credential_ticket_attempts SET state = 'CLAIMED' WHERE operation_id = ?1",
        [[1_u8; 16]],
    )
    .unwrap();
    conn.execute("UPDATE provider_credential_ticket_attempts SET state = 'TOMBSTONED', terminal_digest = ?1 WHERE operation_id = ?2", params![[5_u8; 32], [1_u8; 16]]).unwrap();
    conn.execute("INSERT INTO provider_credential_ticket_attempts (operation_id, attempt, ticket_digest, continuation_binding_digest, issued_at, expires_at, state) VALUES (?1, 2, ?2, ?3, 3, 4, 'ISSUED')", params![[1_u8; 16], [6_u8; 32], [7_u8; 32]]).unwrap();
    assert!(
        conn.execute("DELETE FROM provider_credential_ticket_attempts", [])
            .is_err()
    );
}

#[test]
fn credential_revision_and_fence_never_decrease() {
    let conn = v24_connection();
    conn.execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES ('provider', 1, 1, 1, 1)", []).unwrap();
    assert!(
        conn.execute(
            "UPDATE provider_credential_authority_heads SET lifecycle_revision = 0",
            []
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "UPDATE provider_credential_authority_heads SET credential_fence = 0",
            []
        )
        .is_err()
    );
}

#[test]
fn rollback_cannot_reactivate_tombstoned_version() {
    let conn = v24_connection();
    insert_operation(&conn, 1).unwrap();
    terminal_operation(&conn, 1);
    conn.execute("UPDATE provider_credential_operations SET state = 'TOMBSTONED', tombstone_digest = ?1, updated_at = updated_at + 1", [[9_u8; 32]]).unwrap();
    assert!(
        conn.execute(
            "UPDATE provider_credential_operations SET state = 'PREPARED'",
            []
        )
        .is_err()
    );
}

#[test]
fn pre_v24_versions_are_quarantined_then_cleaned_without_orphans() {
    let conn = Connection::open_in_memory().unwrap();
    apply_migrations_through_v16_for_test(&conn).unwrap();
    conn.execute("INSERT INTO provider_credential_versions VALUES ('legacy', 1, ?1, 'PREPARED', NULL, NULL, NULL, 0, NULL)", [[1_u8; 32]]).unwrap();
    conn.execute("UPDATE provider_credential_versions SET lifecycle_state = 'ACTIVE', lease_owner = ?1, lease_expires_at = 1, lease_fencing_token = 2, revocation_fence = 1 WHERE provider_id = 'legacy'", [[2_u8; 16]]).unwrap();
    apply_migrations(&conn).unwrap();
    let head: (i64, Option<i64>, Vec<u8>, i64) = conn.query_row("SELECT next_credential_version, active_credential_version, pre_v24_quarantine_digest, pre_v24_quarantine_count FROM provider_credential_authority_heads WHERE provider_id = 'legacy'", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).unwrap();
    assert_eq!(head.0, 2);
    assert_eq!(head.1, None);
    assert_ne!(head.2, vec![0; 32]);
    assert_eq!(head.3, 1);
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM provider_credential_operations",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn legacy_cutover_cleanup_insert_failure_rolls_back_everything() {
    let conn = v24_connection();
    let transaction = conn.unchecked_transaction().unwrap();
    transaction.execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES ('provider', 1, 1, 1, 1)", []).unwrap();
    transaction.execute("INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'provider', 'MIGRATE_LEGACY', ?1, 'migration', 1, 1, 1, ?2, 'PREPARED', ?3, 1, 1)", params![[7_u8; 16], [70_u8; 32], [7_u8; 32]]).unwrap();
    transaction.execute("UPDATE provider_credential_operations SET state = 'CLAIMED', continuation_binding_digest = ?1, process_release_binding_digest = ?2, updated_at = updated_at + 1 WHERE operation_id = ?3", params![[7_u8; 32], [8_u8; 32], [7_u8; 16]]).unwrap();
    transaction.execute("UPDATE provider_credential_operations SET state = 'NATIVE_EFFECT_OBSERVED', native_effect_disposition = 'observed', updated_at = updated_at + 1 WHERE operation_id = ?1", [[7_u8; 16]]).unwrap();
    transaction.execute("UPDATE provider_credential_operations SET state = 'READBACK_VERIFIED', readback_observation_digest = ?1, updated_at = updated_at + 1 WHERE operation_id = ?2", params![[9_u8; 32], [7_u8; 16]]).unwrap();
    transaction.execute("UPDATE provider_credential_operations SET state = 'COMPLETED', terminal_disposition = 'completed', updated_at = updated_at + 1 WHERE operation_id = ?1", [[7_u8; 16]]).unwrap();
    transaction.execute("INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'provider', 'LEGACY_SOURCE_CLEANUP', ?1, 'cleanup', 1, 1, 'PREPARED', ?2, 1, 1)", params![[8_u8; 16], [8_u8; 32]]).unwrap();
    transaction.execute("UPDATE provider_credential_authority_heads SET legacy_import_consumed = 1, legacy_source_binding_digest = ?1, legacy_consumed_lifecycle_revision = 2, legacy_cleanup_operation_id = ?2, lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, next_credential_version = 2, active_credential_version = 1, active_ref_digest = ?3 WHERE provider_id = 'provider'", params![[7_u8; 32], [8_u8; 16], [70_u8; 32]]).unwrap();
    assert!(transaction.execute("INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'provider', 'PAIR', ?1, 'duplicate', 1, 1, 'PREPARED', ?2, 1, 1)", params![[7_u8; 16], [9_u8; 32]]).is_err());
    transaction.rollback().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM provider_credential_authority_heads",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn committed_legacy_barrier_has_exactly_one_linked_cleanup() {
    let conn = v24_connection();
    conn.execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES ('provider', 1, 1, 1, 1)", []).unwrap();
    conn.execute("INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'provider', 'MIGRATE_LEGACY', ?1, 'migration', 1, 1, 1, ?2, 'PREPARED', ?3, 1, 1)", params![[8_u8; 16], [80_u8; 32], [8_u8; 32]]).unwrap();
    terminal_operation(&conn, 8);
    conn.execute("INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'provider', 'LEGACY_SOURCE_CLEANUP', ?1, 'cleanup', 1, 1, 'PREPARED', ?2, 1, 1)", params![[9_u8; 16], [9_u8; 32]]).unwrap();
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET legacy_import_consumed = 1, legacy_source_binding_digest = ?1, legacy_consumed_lifecycle_revision = 1, legacy_cleanup_operation_id = ?2 WHERE provider_id = 'provider'", params![[8_u8; 32], [8_u8; 16]]).is_err());
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET legacy_import_consumed = 1, legacy_source_binding_digest = ?1, legacy_consumed_lifecycle_revision = 1, lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, legacy_cleanup_operation_id = ?2, next_credential_version = 2, active_credential_version = 1, active_ref_digest = ?3 WHERE provider_id = 'provider'", params![[8_u8; 32], [9_u8; 16], [80_u8; 32]]).is_err());
    conn.execute("UPDATE provider_credential_authority_heads SET legacy_import_consumed = 1, legacy_source_binding_digest = ?1, legacy_consumed_lifecycle_revision = 2, lifecycle_revision = 2, credential_fence = 2, readiness_revision = 2, legacy_cleanup_operation_id = ?2, next_credential_version = 2, active_credential_version = 1, active_ref_digest = ?3 WHERE provider_id = 'provider'", params![[8_u8; 32], [9_u8; 16], [80_u8; 32]]).unwrap();
    assert_eq!(conn.query_row("SELECT COUNT(*) FROM provider_credential_operations WHERE operation_id = (SELECT legacy_cleanup_operation_id FROM provider_credential_authority_heads WHERE provider_id = 'provider') AND action = 'LEGACY_SOURCE_CLEANUP'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
}

#[test]
fn v24_rejects_tampered_predecessor_ddl_and_trigger() {
    let conn = v24_connection();
    conn.execute_batch(
        "DROP TABLE approvals; CREATE TABLE approvals (approval_id TEXT PRIMARY KEY);",
    )
    .unwrap();
    assert!(!v24_matches(&conn, 24).unwrap());
    let conn = v24_connection();
    conn.execute_batch("DROP TRIGGER provider_credential_transition_order;")
        .unwrap();
    assert!(!v24_matches(&conn, 24).unwrap());
}

#[test]
fn v24_rejects_case_mutated_v24_literals_in_checks_and_partial_indexes() {
    let conn = v24_connection();
    conn.execute_batch("PRAGMA writable_schema=ON; UPDATE sqlite_master SET sql=replace(sql, '''PREPARED''', '''prepared''') WHERE name='provider_credential_operations'; PRAGMA writable_schema=OFF;").unwrap();
    assert!(!v24_matches(&conn, 24).unwrap());
    let conn = v24_connection();
    conn.execute_batch("PRAGMA writable_schema=ON; UPDATE sqlite_master SET sql=replace(sql, '''COMPLETED''', '''completed''') WHERE name='provider_credential_one_non_terminal_operation'; PRAGMA writable_schema=OFF;").unwrap();
    assert!(!v24_matches(&conn, 24).unwrap());
}

#[test]
fn ticket_attempts_require_the_strict_next_number() {
    let conn = v24_connection();
    insert_operation(&conn, 11).unwrap();
    assert!(conn.execute("INSERT INTO provider_credential_ticket_attempts (operation_id, attempt, ticket_digest, continuation_binding_digest, issued_at, expires_at, state) VALUES (?1, 3, ?2, ?3, 1, 2, 'ISSUED')", params![[11_u8; 16], [12_u8; 32], [13_u8; 32]]).is_err());
}

#[test]
fn begin_proof_digest_remains_consumed_after_terminal_operation() {
    let conn = v24_connection();
    insert_operation(&conn, 14).unwrap();
    terminal_operation(&conn, 14);
    assert!(conn.execute("INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'provider', 'PAIR', ?1, 'replay', 1, 1, 'PREPARED', ?2, 1, 1)", params![[15_u8; 16], [14_u8; 32]]).is_err());
}

#[test]
fn legacy_consumed_barrier_is_rejected_on_insert() {
    let conn = v24_connection();
    conn.execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES ('inserted', 1, 1, 1, 1)", []).unwrap();
    conn.execute("INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'inserted', 'LEGACY_SOURCE_CLEANUP', ?1, 'insert-cleanup', 1, 1, 'PREPARED', ?2, 1, 1)", params![[16_u8; 16], [16_u8; 32]]).unwrap();
    assert!(conn.execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version, legacy_import_consumed, legacy_source_binding_digest, legacy_consumed_lifecycle_revision, legacy_cleanup_operation_id) VALUES ('inserted', 1, 1, 1, 1, 1, ?1, 1, ?2)", params![[16_u8; 32], [16_u8; 16]]).is_err());
}

fn v24_connection() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    initialize_released_v23(&conn);
    apply_migrations(&conn).unwrap();
    conn
}

fn current_schema_marker(conn: &Connection) -> i64 {
    conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn insert_operation(conn: &Connection, value: u8) -> rusqlite::Result<usize> {
    conn.execute("INSERT OR IGNORE INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES ('provider', 1, 1, 1, 1)", [])?;
    conn.execute("INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'provider', 'LEGACY_SOURCE_CLEANUP', ?1, ?2, 1, 1, 'PREPARED', ?3, 1, 1)", params![[value; 16], format!("key-{value}"), [value; 32]])
}

fn terminal_operation(conn: &Connection, value: u8) {
    conn.execute("UPDATE provider_credential_operations SET state = 'CLAIMED', continuation_binding_digest = ?1, process_release_binding_digest = ?2, updated_at = updated_at + 1 WHERE operation_id = ?3", params![[value; 32], [value.wrapping_add(1); 32], [value; 16]]).unwrap();
    conn.execute("UPDATE provider_credential_operations SET state = 'NATIVE_EFFECT_OBSERVED', native_effect_disposition = 'observed', updated_at = updated_at + 1 WHERE operation_id = ?1", [[value; 16]]).unwrap();
    conn.execute("UPDATE provider_credential_operations SET state = 'READBACK_VERIFIED', readback_observation_digest = ?1, updated_at = updated_at + 1 WHERE operation_id = ?2", params![[value.wrapping_add(2); 32], [value; 16]]).unwrap();
    conn.execute("UPDATE provider_credential_operations SET state = 'COMPLETED', terminal_disposition = 'completed', updated_at = updated_at + 1 WHERE operation_id = ?1", [[value; 16]]).unwrap();
}
