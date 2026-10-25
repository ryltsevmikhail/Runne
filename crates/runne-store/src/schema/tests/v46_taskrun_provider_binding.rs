#[test]
fn v46_upgrades_v45_and_reopens_with_binding_admission() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider-binding-v46.sqlite");
    let connection = Connection::open(&path).unwrap();
    apply_migrations_internal(&connection, 45).unwrap();
    assert!(v45_matches(&connection, 45).unwrap());
    apply_migrations(&connection).unwrap();
    assert_eq!(schema_marker(&connection), CURRENT_SCHEMA_VERSION);
    assert!(v42_structure_matches(&connection, true).unwrap(), "v42");
    assert!(
        v69_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap(),
        "v43"
    );
    assert!(
        v69_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap(),
        "v44"
    );
    assert!(
        v69_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap(),
        "v45"
    );
    assert!(v69_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap());
    assert!(classify_existing_connection(&connection).is_ok());
    drop(connection);
    let reopened = Connection::open(path).unwrap();
    assert!(classify_existing_connection(&reopened).is_ok());
    assert!(v69_matches(&reopened, CURRENT_SCHEMA_VERSION).unwrap());
}

#[test]
fn v46_admission_rejects_missing_append_only_guards() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch("DROP TRIGGER taskrun_provider_bindings_no_delete;")
        .unwrap();
    assert!(!v69_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}
