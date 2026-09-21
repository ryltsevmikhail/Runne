#[test]
fn v24_to_v25_backfills_begin_proof_expiry_to_closed_sentinel_once() {
    let connection = Connection::open_in_memory().unwrap();
    initialize_released_v23(&connection);
    apply_migrations_internal(&connection, 24).unwrap();
    insert_operation(&connection, 25).unwrap();
    let before: (Vec<u8>, String, Vec<u8>) = connection
        .query_row(
            "SELECT operation_id, idempotency_key, begin_proof_digest FROM provider_credential_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    apply_migrations_internal(&connection, 25).unwrap();

    assert_eq!(current_schema_marker(&connection), 25);
    let after: (Vec<u8>, String, Vec<u8>, i64) = connection
        .query_row(
            "SELECT operation_id, idempotency_key, begin_proof_digest, begin_proof_expires_at_high_water FROM provider_credential_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!((after.0, after.1, after.2), before);
    assert_eq!(after.3, 0);
    assert!(v25_matches(&connection, 25).unwrap());
}

#[test]
fn interrupted_v25_migration_rolls_back_to_exact_v24_and_retries() {
    let connection = Connection::open_in_memory().unwrap();
    initialize_released_v23(&connection);
    apply_migrations_internal(&connection, 24).unwrap();
    insert_operation(&connection, 24).unwrap();

    let transaction = connection.unchecked_transaction().unwrap();
    transaction.execute_batch(MIGRATION_V25).unwrap();
    assert!(
        transaction
            .execute_batch("CREATE TABLE interrupted_v25 (")
            .is_err()
    );
    transaction.rollback().unwrap();
    assert_eq!(current_schema_marker(&connection), 24);
    assert!(
        connection
            .execute(
                "SELECT begin_proof_expires_at_high_water FROM provider_credential_operations",
                []
            )
            .is_err()
    );
    apply_migrations_internal(&connection, 25).unwrap();
    assert_eq!(current_schema_marker(&connection), 25);
    let migrated: (Vec<u8>, i64) = connection
        .query_row(
            "SELECT operation_id, begin_proof_expires_at_high_water FROM provider_credential_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(migrated, (vec![24; 16], 0));
    assert!(v25_matches(&connection, 25).unwrap());
}

#[test]
fn corrupt_v25_begin_expiry_shape_or_trigger_is_rejected_before_open() {
    let connection = Connection::open_in_memory().unwrap();
    initialize_released_v23(&connection);
    apply_migrations_internal(&connection, 25).unwrap();

    connection
        .execute_batch("DROP TRIGGER provider_credential_ticket_insert_issued;")
        .unwrap();
    assert!(classify_existing_connection(&connection).is_err());
}

#[test]
fn v25_matcher_rejects_an_extra_operation_column() {
    let connection = Connection::open_in_memory().unwrap();
    initialize_released_v23(&connection);
    apply_migrations_internal(&connection, 25).unwrap();
    connection
        .execute_batch("ALTER TABLE provider_credential_operations ADD COLUMN tampered INTEGER")
        .unwrap();

    assert!(classify_existing_connection(&connection).is_err());
}

#[test]
fn v25_matcher_rejects_tampered_inherited_table_index_trigger_and_marker() {
    for statement in [
        "ALTER TABLE provider_credential_ticket_attempts ADD COLUMN tampered INTEGER",
        "DROP INDEX provider_credential_one_non_terminal_operation",
        "DROP TRIGGER provider_credential_operation_insert_prepared",
        "DROP TRIGGER provider_credential_ticket_transition",
        "DELETE FROM schema_version WHERE version=25",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        initialize_released_v23(&connection);
        apply_migrations_internal(&connection, 25).unwrap();
        connection.execute_batch(statement).unwrap();
        assert!(
            classify_existing_connection(&connection).is_err(),
            "tamper was accepted: {statement}"
        );
    }
}

#[test]
fn v24_backfill_loads_but_cannot_reauthorize_begin() {
    let connection = Connection::open_in_memory().unwrap();
    initialize_released_v23(&connection);
    apply_migrations_internal(&connection, 24).unwrap();
    insert_operation(&connection, 26).unwrap();
    apply_migrations_internal(&connection, 25).unwrap();

    let expiry: i64 = connection.query_row("SELECT begin_proof_expires_at_high_water FROM provider_credential_operations WHERE operation_id=?1", [[26_u8; 16]], |row| row.get(0)).unwrap();
    assert_eq!(expiry, 0);
    assert!(connection.execute("INSERT INTO provider_credential_ticket_attempts (operation_id, attempt, ticket_digest, continuation_binding_digest, issued_at, expires_at, state) VALUES (?1, 1, ?2, ?3, 1, 2, 'ISSUED')", rusqlite::params![[26_u8; 16], [27_u8; 32], [28_u8; 32]]).is_err());
}

#[test]
fn v24_non_terminal_sentinel_row_is_rejected_by_v28_open() {
    let directory = tempfile::tempdir().unwrap();
    let path = { let daemon = directory.path().join("runne-daemon"); std::fs::create_dir_all(&daemon).unwrap(); daemon.join("v24-sentinel.sqlite") };
    let connection = Connection::open(&path).unwrap();
    initialize_released_v23(&connection);
    apply_migrations_internal(&connection, 24).unwrap();
    insert_operation(&connection, 27).unwrap();
    apply_migrations_internal(&connection, 27).unwrap();
    let predecessor: (String, i64) = connection
        .query_row(
            "SELECT state, begin_proof_expires_at_high_water
             FROM provider_credential_operations WHERE operation_id=?1",
            [[27_u8; 16]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(predecessor, ("PREPARED".to_owned(), 0));
    assert_eq!(current_schema_marker(&connection), 27);
    drop(connection);

    assert_eq!(
        crate::provider::SqliteProviderCredentialLifecycleStore::open(&path).err(),
        Some(runne_provider::CredentialLifecycleError::StoreUnavailable)
    );
    let connection = Connection::open(&path).unwrap();
    assert_eq!(current_schema_marker(&connection), 27);
}

#[test]
fn v25_matcher_accepts_its_own_successor_shape() {
    let connection = Connection::open_in_memory().unwrap();
    initialize_released_v23(&connection);
    apply_migrations_internal(&connection, 25).unwrap();

    assert!(v24_predecessor_matches(&connection).unwrap(), "predecessor");
    assert!(v24_catalog_matches(&connection).unwrap(), "catalog");
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).unwrap();
    assert_eq!(marker, (25, 1, 24, 306));
    assert!(
        v25_marker_matches(&connection).unwrap(),
        "marker: {marker:?}"
    );
    assert!(
        v25_operation_table_matches(&connection).unwrap(),
        "operation table"
    );
    for (name, source) in V24_TRIGGERS {
        let expected = if V25_REPLACED_TRIGGERS.contains(&name) {
            v25_trigger(name, source)
        } else {
            source.to_owned()
        };
        assert!(
            v24_trigger_matches(&connection, name, &expected).unwrap(),
            "{name}"
        );
    }
}
