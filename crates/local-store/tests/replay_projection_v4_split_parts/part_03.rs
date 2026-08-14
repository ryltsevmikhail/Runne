#[test]
fn rollback_reupgrade_with_existing_pre_v4_backup_is_blocked_without_reuse() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    drop(create_v3_database(&path));
    drop(LocalStore::open(&path).expect("first migration creates backup"));
    let backup_path = pre_v4_migration_backup_path(&path).expect("backup path");
    let held_v4 = directory.path().join("profile.sqlite3.v4-held");
    std::fs::rename(&path, &held_v4).expect("hold migrated v4 database");
    std::fs::copy(&backup_path, &path).expect("restore v3 rollback copy");
    {
        let connection = Connection::open(&path).expect("open restored v3");
        connection
            .execute(
                "UPDATE settings SET value = 'dark' WHERE key = 'appearance.theme'",
                [],
            )
            .expect("mutate restored v3 after rollback");
    }

    let Err(error) = LocalStore::open(&path) else {
        panic!("stale backup reuse must block re-upgrade");
    };

    assert!(matches!(error, StoreOpenError::MigrationBackupUnavailable));
    let connection = Connection::open(&path).expect("reopen restored v3 after blocked re-upgrade");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("version");
    let theme: String = connection
        .query_row(
            "SELECT value FROM settings WHERE key = 'appearance.theme'",
            [],
            |row| row.get(0),
        )
        .expect("post-rollback v3 state");
    assert_eq!(version, 3);
    assert_eq!(theme, "dark");
}

#[test]
fn empty_base_v4_schema_is_upgraded_before_replay_use() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    drop(create_base_v4_database(&path, false));

    let mut store = LocalStore::open(&path).expect("upgrade empty base v4 replay schema");
    assert_eq!(
        store.get_setting("appearance.theme").expect("read setting"),
        Some("light".into())
    );
    assert_eq!(store.list_projects().expect("list projects")[0].id, 41);

    let scope = scope();
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let outcome = store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            br#"{"eventId":"event-1","sequence":1}"#,
            0,
            projection,
        ))
        .expect("apply transition after base v4 upgrade");
    assert_eq!(
        outcome,
        ReplayApplyOutcome::Applied {
            database_generation: 10
        }
    );
    assert_eq!(
        store
            .conversation_projection(&scope)
            .expect("read projection")
            .expect("stored projection")
            .payload,
        projection
    );

    drop(store);
    let connection = Connection::open(path).expect("inspect upgraded schema");
    for column in [
        "projection_revision",
        "projection_digest",
        "projected_payload",
    ] {
        let present: bool = connection
            .query_row(
                "
                SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('event_journal') WHERE name = ?1
                )
                ",
                [column],
                |row| row.get(0),
            )
            .expect("inspect projection identity column");
        assert!(present, "missing event_journal.{column}");
    }
}

#[test]
fn non_empty_base_v4_replay_state_is_rejected_before_any_mutation() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    drop(create_base_v4_database(&path, true));

    let Err(error) = LocalStore::open(&path) else {
        panic!("base v4 replay state without projection identity must fail closed");
    };
    assert!(matches!(error, StoreOpenError::LegacyReplayState));

    let connection = Connection::open(path).expect("inspect rejected database");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read schema version");
    let event: Vec<u8> = connection
        .query_row("SELECT validated_event FROM event_journal", [], |row| {
            row.get(0)
        })
        .expect("read preserved event");
    let cursor: String = connection
        .query_row("SELECT applied_cursor FROM replay_cursors", [], |row| {
            row.get(0)
        })
        .expect("read preserved cursor");
    let projection: Vec<u8> = connection
        .query_row("SELECT payload FROM projections", [], |row| row.get(0))
        .expect("read preserved projection");
    let setting: String = connection
        .query_row(
            "SELECT value FROM settings WHERE key = 'appearance.theme'",
            [],
            |row| row.get(0),
        )
        .expect("read preserved setting");
    let new_column_present: bool = connection
        .query_row(
            "
            SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('event_journal')
                WHERE name = 'projected_payload'
            )
            ",
            [],
            |row| row.get(0),
        )
        .expect("inspect rejected schema");
    assert_eq!(version, 4);
    assert_eq!(event, br#"{"eventId":"event-1","sequence":1}"#);
    assert_eq!(cursor, "opaque.cursor.1");
    assert_eq!(
        projection,
        br#"{"conversationId":"conversation-1","messages":[]}"#
    );
    assert_eq!(setting, "light");
    assert!(!new_column_present);
}

#[test]
fn non_empty_v3_replay_state_is_rejected_before_any_mutation() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let connection = create_v3_database(&path);
    connection
        .execute(
            "
            INSERT INTO replay_cursors (
                runtime_authority, principal, lineage, scope, generation, applied_cursor
            ) VALUES ('runtime-1', 'principal-1', 'lineage-1', 'conversation-1', 7, 'opaque')
            ",
            [],
        )
        .expect("insert legacy replay state");
    drop(connection);

    let Err(error) = LocalStore::open(&path) else {
        panic!("legacy replay state must fail closed");
    };
    assert!(matches!(error, StoreOpenError::LegacyReplayState));

    let connection = Connection::open(path).expect("inspect rejected database");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read schema version");
    let cursor: String = connection
        .query_row("SELECT applied_cursor FROM replay_cursors", [], |row| {
            row.get(0)
        })
        .expect("read preserved cursor");
    let setting: String = connection
        .query_row(
            "SELECT value FROM settings WHERE key = 'appearance.theme'",
            [],
            |row| row.get(0),
        )
        .expect("read preserved setting");
    assert_eq!(version, 3);
    assert_eq!(cursor, "opaque");
    assert_eq!(setting, "light");
}

#[test]
fn schema_newer_than_v5_is_rejected_without_rewrite() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let connection = Connection::open(&path).expect("create database");
    connection
        .pragma_update(None, "user_version", 6)
        .expect("set future version");
    drop(connection);

    let Err(error) = LocalStore::open(&path) else {
        panic!("future schema must fail");
    };
    assert!(matches!(error, StoreOpenError::UnsupportedSchema(6)));
    let connection = Connection::open(path).expect("reopen future database");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read future version");
    assert_eq!(version, 6);
}
