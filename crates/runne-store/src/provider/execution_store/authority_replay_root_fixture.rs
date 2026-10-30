fn drop_empty_root_binding_fixture(connection: &Connection) {
    let root_bindings: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM workspace_root_identities",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        root_bindings, 0,
        "historical fixture must not discard root bindings"
    );
    connection
        .execute_batch("DROP TABLE workspace_root_identities")
        .unwrap();
}
