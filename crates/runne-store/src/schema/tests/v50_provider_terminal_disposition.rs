#[test]
fn v50_provider_terminal_dispositions_are_strict_and_append_only() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 50).unwrap();
    assert_eq!(schema_marker(&connection), 50);
    assert!(v50_matches(&connection, 50).unwrap());
    let ddl: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_terminal_dispositions'",
        [], |row| row.get(0),
    ).unwrap();
    assert!(ddl.contains("disposition IN (1,2,3,4)"));
    connection
        .execute("DROP TRIGGER provider_terminal_dispositions_immutable", [])
        .unwrap();
    assert!(!v50_matches(&connection, 50).unwrap());
}

#[test]
fn v50_partial_migration_is_not_classified_as_released() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 50).unwrap();
    connection
        .execute("DROP TABLE provider_terminal_dispositions", [])
        .unwrap();
    assert!(!v50_matches(&connection, 50).unwrap());
}
