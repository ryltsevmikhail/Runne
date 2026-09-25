#[test]
fn v35_upgrades_to_exact_v36_irreversible_revoke_catalog() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 35).unwrap();
    assert!(v35_matches(&connection, 35).unwrap());

    apply_migrations(&connection).unwrap();

    assert!(v36_matches(&connection, 36).unwrap());
    assert_eq!(classify_schema_version(&connection).unwrap(), 36);
}

#[test]
fn v36_rejects_missing_or_tampered_irreversible_revoke_trigger() {
    for mutation in [
        "DROP TRIGGER provider_credential_revoke_irreversible",
        "DROP TRIGGER provider_credential_revoke_irreversible;
         CREATE TRIGGER provider_credential_revoke_irreversible
         BEFORE UPDATE ON provider_credential_operations BEGIN SELECT 1; END",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations(&connection).unwrap();
        assert!(v36_matches(&connection, 36).unwrap());
        connection.execute_batch(mutation).unwrap();
        assert!(!v36_matches(&connection, 36).unwrap(), "{mutation}");
    }
}
