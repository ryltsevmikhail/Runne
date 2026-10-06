#[test]
fn v60_adds_append_only_remote_artifact_cancel_closure_and_accepts_exact_markers() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 59).unwrap();
    apply_migrations_internal(&connection, 60).unwrap();
    assert_eq!(schema_marker(&connection), 60);
    assert!(v60_matches(&connection, 60).unwrap());
    assert!(v42_structure_matches(&connection, true).unwrap());
    assert!(v59_matches(&connection, 60).unwrap());
    let ddl: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_remote_artifact_cancel_closures'",
        [], |row| row.get(0),
    ).unwrap();
    for required in [
        "cancellation_command_id BLOB NOT NULL",
        "cancellation_event_id BLOB NOT NULL",
        "taskrun_terminal_event_id BLOB NOT NULL",
        "observed_conversation_head_event_id BLOB NOT NULL",
        "CHECK((conversation_terminal_event_id IS NULL)=(conversation_terminal_version IS NULL))",
        "FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_remote_terminal_settlements",
    ] {
        assert!(ddl.contains(required), "missing DDL contract: {required}");
    }
}

#[test]
fn v60_readiness_rejects_missing_append_only_guards() {
    for trigger in [
        "provider_remote_artifact_cancel_closures_immutable",
        "provider_remote_artifact_cancel_closures_no_delete",
        "schema_v12_fence_provider_remote_artifact_cancel_closures_insert",
        "schema_v12_fence_provider_remote_artifact_cancel_closures_update",
        "schema_v12_fence_provider_remote_artifact_cancel_closures_delete",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 60).unwrap();
        connection
            .execute_batch(&format!("DROP TRIGGER {trigger}"))
            .unwrap();
        assert!(!v60_matches(&connection, 60).unwrap(), "{trigger}");
    }
}

#[cfg(unix)]
#[test]
fn v60_validated_reopen_after_managed_v59_upgrade() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = daemon.join("remote-cancel.db");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations_internal(&connection, 59).unwrap();
    drop(connection);

    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    drop(connection);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let reopened =
        reopen_managed_connection_validated(&path, ConnectionMode::ValidatedReopen, |connection| {
            assert_eq!(schema_marker(connection), CURRENT_SCHEMA_VERSION);
            assert!(v65_matches(connection, CURRENT_SCHEMA_VERSION)?);
            Ok(())
        })
        .unwrap();
    assert_eq!(schema_marker(&reopened), CURRENT_SCHEMA_VERSION);
}
