#[test]
fn v45_upgrades_v44_with_release_receipt_guards() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 44).unwrap();
    assert!(v44_matches(&connection, 44).unwrap());
    apply_migrations(&connection).unwrap();
    assert!(v42_structure_matches(&connection, true).unwrap(), "inherited V42 admission");
    assert!(v43_matches(&connection,45).unwrap(), "inherited V43 admission");
    assert!(v44_matches(&connection,45).unwrap(), "inherited V44 admission");
    assert_eq!(schema_marker(&connection),46);
    assert!(v46_matches(&connection, 46).unwrap());
    assert!(classify_existing_connection(&connection).is_ok());
}

#[test]
fn v45_admission_rejects_missing_receipt_guards() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection.execute_batch("DROP TRIGGER global_command_id_from_release_v45;").unwrap();
    assert!(!v46_matches(&connection, 46).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}
