#[test]
fn v68_migrates_clean_v67_schema_with_empty_routes() {
    let path = std::env::temp_dir().join(format!(
        "runne-v68-permission-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    {
        let connection = Connection::open(&path).unwrap();
        apply_migrations_internal(&connection, 67).unwrap();
        apply_migrations_internal(&connection, 68).unwrap();
        let routes: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM taskrun_local_permission_routes",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(routes, 0);
        assert!(v68_matches(&connection, 68).unwrap());
        assert!(!v68_matches(&connection, 67).unwrap());
        assert!(!v68_matches(&connection, 69).unwrap());
        assert!(!v67_matches(&connection, 67).unwrap());
    }
    let reopened = Connection::open(&path).unwrap();
    assert!(v68_matches(&reopened, 68).unwrap());
    drop(reopened);
    let _ = std::fs::remove_file(path);
}

#[test]
fn v68_rejects_ambiguous_historical_local_command_rows() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 67).unwrap();
    insert_v68_preflight(&connection, [0x32; 16], "approved");

    assert!(apply_migrations_internal(&connection, 68).is_err());
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 67);
}

#[test]
fn v68_runtime_inserts_only_immutable_new_routes() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    insert_v68_preflight(&connection, [0x33; 16], "preflight");
    assert!(!v68_matches(&connection, 68).unwrap());
    connection
        .execute(
            "INSERT INTO taskrun_local_permission_routes
         (taskrun_id,route,provenance,cutover_version) VALUES (?1,2,3,68)",
            [&[0x33; 16][..]],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                "UPDATE taskrun_local_permission_routes SET route=1 WHERE taskrun_id=?1",
                [&[0x33; 16][..]],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM taskrun_local_permission_routes WHERE taskrun_id=?1",
                [&[0x33; 16][..]],
            )
            .is_err()
    );
    let route: (i64, i64) = connection
        .query_row(
            "SELECT route,provenance FROM taskrun_local_permission_routes WHERE taskrun_id=?1",
            [&[0x33; 16][..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(route, (2, 3));
    assert!(
        connection
            .execute(
                "INSERT OR REPLACE INTO taskrun_local_permission_routes
         (taskrun_id,route,provenance,cutover_version) VALUES (?1,1,1,68)",
                [&[0x33; 16][..]],
            )
            .is_err()
    );
}

#[test]
fn v68_whole_matcher_rejects_route_catalog_tampering_and_marker_only_upgrade() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute("DROP TRIGGER taskrun_local_permission_routes_immutable", [])
        .unwrap();
    assert!(!v68_matches(&connection, 68).unwrap());

    let marker_only = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&marker_only, 67).unwrap();
    marker_only
        .execute("INSERT INTO schema_version(version) VALUES(68)", [])
        .unwrap();
    assert!(!v68_matches(&marker_only, 68).unwrap());
}

#[test]
fn v68_no_effect_proof_fails_closed_without_retained_capture_or_receipt() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    let taskrun = runne_domain::id::TaskRunId::from_bytes([0x35; 16]);
    insert_v68_preflight(&connection, *taskrun.as_bytes(), "preflight");
    connection
        .execute(
            "INSERT INTO taskrun_local_permission_routes
             (taskrun_id,route,provenance,cutover_version) VALUES (?1,2,3,68)",
            [taskrun.as_bytes()],
        )
        .unwrap();

    assert!(crate::store::taskrun_local_command::permission::no_effect::current_route(
        &connection, taskrun
    )
    .unwrap());
    assert!(!crate::store::taskrun_local_command::permission::no_effect::pre_release_matches(
        &connection,
        taskrun,
        runne_domain::id::AttemptId::from_bytes([0x36; 16]),
        &runne_application::ports::RuntimeAuthorityId("test-authority".into()),
    )
    .unwrap());
    assert!(!crate::store::taskrun_local_command::permission::no_effect::settled_matches(
        &connection, taskrun
    )
    .unwrap());
}

fn insert_v68_preflight(connection: &Connection, taskrun_id: [u8; 16], state: &str) {
    connection
        .execute(
            "INSERT INTO taskrun_local_command_attempts
             (taskrun_id,conversation_id,workspace_id,command_digest,state,updated_at)
             VALUES (?1,?2,?3,?4,?5,1)",
            rusqlite::params![
                taskrun_id.as_slice(),
                [0x41_u8; 16].as_slice(),
                [0x42_u8; 16].as_slice(),
                [0x43_u8; 32].as_slice(),
                state
            ],
        )
        .unwrap();
}
