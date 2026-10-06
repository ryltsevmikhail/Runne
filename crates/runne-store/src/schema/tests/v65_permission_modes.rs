#[test]
fn v65_adds_permission_mode_tables_and_is_admitted_as_current_schema() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 64).unwrap();
    assert!(v64_matches(&connection, 64).unwrap());
    apply_migrations_internal(&connection, 65).unwrap();
    assert_eq!(schema_marker(&connection), 65);
    assert!(v65_matches(&connection, 65).unwrap());
    for table in [
        "permission_mode_selections",
        "permission_mode_command_receipts",
        "permission_mode_native_challenges",
    ] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present, "missing {table}");
    }
}

#[test]
fn v65_selection_revision_is_monotonic_and_append_only() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute(
            "INSERT INTO permission_mode_selections (
            runtime_authority_id,principal_id,workspace_id,project_id,selected_mode,preset_version,
            authorization_revision,managed_policy_version,managed_policy_digest,expires_at_unix_ms,
            last_command_id,intent_digest,updated_at_unix_ms
         ) VALUES ('authority','principal',zeroblob(16),zeroblob(16),1,1,1,0,zeroblob(32),NULL,
            zeroblob(16),zeroblob(32),1)",
            [],
        )
        .unwrap();
    connection.execute(
        "UPDATE permission_mode_selections SET authorization_revision=2 WHERE runtime_authority_id='authority'",
        [],
    ).unwrap();
    assert!(connection.execute(
        "UPDATE permission_mode_selections SET authorization_revision=4 WHERE runtime_authority_id='authority'",
        [],
    ).is_err());
    assert!(
        connection
            .execute(
                "DELETE FROM permission_mode_selections WHERE runtime_authority_id='authority'",
                [],
            )
            .is_err()
    );
}

#[test]
fn v65_catalog_rejects_missing_permission_mode_guard() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    assert!(v65_matches(&connection, 65).unwrap());
    connection
        .execute_batch("DROP TRIGGER permission_mode_native_challenge_update")
        .unwrap();
    assert!(!v65_matches(&connection, 65).unwrap());
}

#[test]
fn v65_startup_rejects_unrecognized_permission_mode_schema_drift() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch("DROP INDEX idx_permission_mode_challenges_pending")
        .unwrap();
    assert!(classify_schema_version(&connection).is_err());
}
