#[test]
fn v30_binds_credential_verification_to_current_readiness_and_release() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();

    assert_eq!(CURRENT_SCHEMA_VERSION, 31);
    assert!(v30_predecessor_matches_with(&connection, &v31_trigger()).unwrap());
    assert!(v30_columns_match(&connection).unwrap());
    for name in V30_TRIGGERS {
        assert!(v24_trigger_matches(&connection, name, v30_trigger_source(name)).unwrap());
    }
    assert!(v31_matches(&connection, 31).unwrap());

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("v30.sqlite");
    let file = Connection::open(&path).unwrap();
    apply_migrations(&file).unwrap();
    drop(file);
    let reopened = Connection::open(path).unwrap();
    assert!(v31_matches(&reopened, 31).unwrap());
}
