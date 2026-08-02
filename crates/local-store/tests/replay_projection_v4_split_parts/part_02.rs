#[allow(clippy::too_many_lines)]
fn create_base_v4_database(path: &Path, with_replay_state: bool) -> Connection {
    let connection = create_v3_database(path);
    connection
        .execute_batch(
            "
            DROP TABLE projections;
            DROP TABLE event_journal;
            DROP TABLE replay_cursors;

            CREATE TABLE projections (
                runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0),
                principal TEXT NOT NULL CHECK (length(principal) > 0),
                lineage TEXT NOT NULL CHECK (length(lineage) > 0),
                scope TEXT NOT NULL CHECK (length(scope) > 0),
                binding_digest TEXT NOT NULL CHECK (
                    length(binding_digest) = 64
                    AND binding_digest NOT GLOB '*[^0-9a-f]*'
                ),
                projection_revision INTEGER NOT NULL CHECK (projection_revision >= 0),
                projection_digest TEXT NOT NULL CHECK (
                    length(projection_digest) = 64
                    AND projection_digest NOT GLOB '*[^0-9a-f]*'
                ),
                event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
                payload BLOB NOT NULL CHECK (json_valid(payload) = 1),
                PRIMARY KEY (runtime_authority, principal, lineage, scope)
            ) STRICT;

            CREATE TABLE event_journal (
                runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0),
                principal TEXT NOT NULL CHECK (length(principal) > 0),
                lineage TEXT NOT NULL CHECK (length(lineage) > 0),
                scope TEXT NOT NULL CHECK (length(scope) > 0),
                binding_digest TEXT NOT NULL CHECK (
                    length(binding_digest) = 64
                    AND binding_digest NOT GLOB '*[^0-9a-f]*'
                ),
                event_id TEXT NOT NULL CHECK (length(event_id) > 0),
                cursor TEXT NOT NULL CHECK (length(cursor) > 0),
                generation INTEGER NOT NULL CHECK (generation >= 0),
                event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
                validated_event BLOB NOT NULL,
                event_digest TEXT NOT NULL CHECK (
                    length(event_digest) = 64
                    AND event_digest NOT GLOB '*[^0-9a-f]*'
                ),
                PRIMARY KEY (
                    runtime_authority,
                    principal,
                    lineage,
                    scope,
                    event_id
                ),
                UNIQUE (
                    runtime_authority,
                    principal,
                    lineage,
                    scope,
                    event_sequence
                ),
                UNIQUE (
                    runtime_authority,
                    principal,
                    lineage,
                    scope,
                    cursor
                )
            ) STRICT;

            CREATE TABLE replay_cursors (
                runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0),
                principal TEXT NOT NULL CHECK (length(principal) > 0),
                lineage TEXT NOT NULL CHECK (length(lineage) > 0),
                scope TEXT NOT NULL CHECK (length(scope) > 0),
                binding_digest TEXT NOT NULL CHECK (
                    length(binding_digest) = 64
                    AND binding_digest NOT GLOB '*[^0-9a-f]*'
                ),
                generation INTEGER NOT NULL CHECK (generation >= 0),
                applied_cursor TEXT NOT NULL CHECK (length(applied_cursor) > 0),
                event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
                projection_revision INTEGER NOT NULL CHECK (projection_revision >= 0),
                projection_digest TEXT NOT NULL CHECK (
                    length(projection_digest) = 64
                    AND projection_digest NOT GLOB '*[^0-9a-f]*'
                ),
                PRIMARY KEY (runtime_authority, principal, lineage, scope)
            ) STRICT;

            UPDATE meta SET schema_version = 4 WHERE singleton = 1;
            PRAGMA user_version = 4;
            ",
        )
        .expect("create base v4 schema");

    if with_replay_state {
        let event = br#"{"eventId":"event-1","sequence":1}"#;
        let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
        connection
            .execute(
                "
                INSERT INTO event_journal (
                    runtime_authority, principal, lineage, scope, binding_digest,
                    event_id, cursor, generation, event_sequence, validated_event, event_digest
                ) VALUES (
                    'runtime-1', 'principal-1', 'lineage-1', 'conversation-1', ?1,
                    'event-1', 'opaque.cursor.1', 3, 1, ?2, ?3
                )
                ",
                params![BINDING_DIGEST, event, digest(event)],
            )
            .expect("insert base v4 event");
        connection
            .execute(
                "
                INSERT INTO projections (
                    runtime_authority, principal, lineage, scope, binding_digest,
                    projection_revision, projection_digest, event_sequence, payload
                ) VALUES (
                    'runtime-1', 'principal-1', 'lineage-1', 'conversation-1', ?1,
                    1, ?2, 1, ?3
                )
                ",
                params![BINDING_DIGEST, digest(projection), projection],
            )
            .expect("insert base v4 projection");
        connection
            .execute(
                "
                INSERT INTO replay_cursors (
                    runtime_authority, principal, lineage, scope, binding_digest,
                    generation, applied_cursor, event_sequence, projection_revision,
                    projection_digest
                ) VALUES (
                    'runtime-1', 'principal-1', 'lineage-1', 'conversation-1', ?1,
                    3, 'opaque.cursor.1', 1, 1, ?2
                )
                ",
                params![BINDING_DIGEST, digest(projection)],
            )
            .expect("insert base v4 cursor");
    }

    connection
}

#[test]
fn empty_v3_replay_tables_migrate_to_v4_without_touching_settings_or_projects() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    drop(create_v3_database(&path));

    let store = LocalStore::open(&path).expect("migrate empty v3 replay state");

    assert_eq!(store.diagnostics().expect("diagnostics").schema_version, 4);
    assert_eq!(
        store.get_setting("appearance.theme").expect("read setting"),
        Some("light".into())
    );
    let projects = store.list_projects().expect("list projects");
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].id, 41);
    assert_eq!(projects[0].name, "preserved");

    drop(store);
    let connection = Connection::open(path).expect("inspect v4 schema");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read schema version");
    assert_eq!(version, 4);
    for (table, column) in [
        ("event_journal", "binding_digest"),
        ("event_journal", "event_sequence"),
        ("event_journal", "projection_revision"),
        ("event_journal", "projection_digest"),
        ("event_journal", "projected_payload"),
        ("projections", "projection_revision"),
        ("projections", "projection_digest"),
        ("replay_cursors", "event_sequence"),
        ("replay_cursors", "projection_digest"),
    ] {
        let present: bool = connection
            .query_row(
                "
                SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2
                )
                ",
                params![table, column],
                |row| row.get(0),
            )
            .expect("inspect v4 column");
        assert!(present, "missing {table}.{column}");
    }
}

#[test]
fn v3_to_v4_migration_creates_a_reopenable_integrity_checked_rollback_backup() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    drop(create_v3_database(&path));

    drop(LocalStore::open(&path).expect("migrate with rollback backup"));

    let backup_path = pre_v4_migration_backup_path(&path).expect("backup path");
    let backup = verify_pre_v4_migration_backup(&path).expect("verified rollback backup");
    assert_eq!(backup.path, backup_path);
    assert_eq!(backup.schema_version, 3);
    let backup_connection = Connection::open(&backup.path).expect("reopen rollback backup");
    let integrity: String = backup_connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("backup integrity");
    let theme: String = backup_connection
        .query_row(
            "SELECT value FROM settings WHERE key = 'appearance.theme'",
            [],
            |row| row.get(0),
        )
        .expect("preserved setting");
    assert_eq!(integrity, "ok");
    assert_eq!(theme, "light");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&backup.path)
                .expect("backup metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn invalid_existing_pre_v4_backup_blocks_migration_without_rewriting_v3() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    drop(create_v3_database(&path));
    let backup_path = pre_v4_migration_backup_path(&path).expect("backup path");
    std::fs::write(&backup_path, b"not a sqlite backup").expect("corrupt backup fixture");

    let Err(error) = LocalStore::open(&path) else {
        panic!("invalid backup must block migration");
    };

    assert!(matches!(error, StoreOpenError::MigrationBackupUnavailable));
    let connection = Connection::open(path).expect("reopen original v3");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("original version");
    assert_eq!(version, 3);
}
