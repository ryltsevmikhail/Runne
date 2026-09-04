#[test]
fn v30_binds_credential_verification_to_current_readiness_and_release() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 30).unwrap();

    assert!(v30_predecessor_matches(&connection).unwrap());
    assert!(v30_columns_match(&connection).unwrap());
    for name in V30_TRIGGERS {
        assert!(v24_trigger_matches(&connection, name, v30_trigger_source(name)).unwrap());
    }
    assert!(v30_matches(&connection, 30).unwrap());

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("v30.sqlite");
    let file = Connection::open(&path).unwrap();
    apply_migrations_internal(&file, 30).unwrap();
    drop(file);
    let reopened = Connection::open(path).unwrap();
    assert!(v30_matches(&reopened, 30).unwrap());
}
