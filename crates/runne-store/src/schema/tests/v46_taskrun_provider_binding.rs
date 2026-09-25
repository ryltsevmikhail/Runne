#[test]
fn v46_upgrades_v45_and_reopens_with_binding_admission() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider-binding-v46.sqlite");
    let connection = Connection::open(&path).unwrap();
    apply_migrations_internal(&connection, 45).unwrap();
    assert!(v45_matches(&connection, 45).unwrap());
    apply_migrations(&connection).unwrap();
    assert_eq!(schema_marker(&connection), 46);
    assert!(v42_structure_matches(&connection, true).unwrap(), "v42");
    assert!(v43_matches(&connection, 46).unwrap(), "v43");
    assert!(v44_matches(&connection, 46).unwrap(), "v44");
    assert!(v45_matches(&connection, 46).unwrap(), "v45");
    assert!(v46_matches(&connection, 46).unwrap());
    assert!(classify_existing_connection(&connection).is_ok());
    drop(connection);
    let reopened = Connection::open(path).unwrap();
    assert!(classify_existing_connection(&reopened).is_ok());
    assert!(v46_matches(&reopened, 46).unwrap());
}

#[test]
fn v46_admission_rejects_missing_append_only_guards() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch("DROP TRIGGER taskrun_provider_bindings_no_delete;")
        .unwrap();
    assert!(!v46_matches(&connection, 46).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}
