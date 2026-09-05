#[test]
fn v34_upgrades_to_exact_v35_overlap_catalog() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 34).unwrap();
    assert!(v34_matches(&connection, 34).unwrap());

    apply_migrations_internal(&connection, 35).unwrap();

    assert!(v35_matches(&connection, 35).unwrap());
    assert_eq!(classify_schema_version(&connection).unwrap(), 35);
}

#[test]
fn v35_rejects_missing_or_tampered_cleanup_serialization_indexes() {
    for mutation in [
        "DROP INDEX provider_credential_one_pending_retired_version_cleanup",
        "DROP INDEX provider_credential_one_non_terminal_operation;
         CREATE UNIQUE INDEX provider_credential_one_non_terminal_operation
         ON provider_credential_operations(provider_id)
         WHERE state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED')",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 35).unwrap();
        assert!(v35_matches(&connection, 35).unwrap());
        connection.execute_batch(mutation).unwrap();
        assert!(!v35_matches(&connection, 35).unwrap(), "{mutation}");
    }
}
