use std::path::Path;

use gocode_local_store::{
    AppliedReplayEvent, LocalStore, ReplayApplyOutcome, ReplayCheckpoint, ReplayScopeKey,
    ReplayStoreError, ReplayTransition, StoreOpenError,
};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

const BINDING_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_BINDING_DIGEST: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn scope() -> ReplayScopeKey {
    ReplayScopeKey {
        runtime_authority: "runtime-1".into(),
        principal: "principal-1".into(),
        lineage: "lineage-1".into(),
        scope: "conversation-1".into(),
        binding_digest: BINDING_DIGEST.into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn transition<'a>(
    scope: &'a ReplayScopeKey,
    expected_checkpoint: Option<&'a ReplayCheckpoint>,
    event_id: &'a str,
    cursor: &'a str,
    generation: u64,
    event_sequence: u64,
    event_bytes: &'a [u8],
    projection_revision: u64,
    projection_bytes: &'a [u8],
) -> ReplayTransition<'a> {
    ReplayTransition {
        scope,
        expected_checkpoint,
        event_id,
        cursor,
        generation,
        event_sequence,
        event_bytes,
        event_digest: digest(event_bytes),
        projection_revision,
        projection_bytes,
        projection_digest: digest(projection_bytes),
    }
}

fn create_v3_database(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("create v3 database");
    connection
        .execute_batch(
            "
            CREATE TABLE settings (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL,
                revision INTEGER NOT NULL DEFAULT 1
            ) STRICT;
            INSERT INTO settings (key, value) VALUES ('appearance.theme', 'light');

            CREATE TABLE projects (
                id INTEGER PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                last_opened_at INTEGER NOT NULL
            ) STRICT;
            INSERT INTO projects (id, name, path, last_opened_at)
            VALUES (41, 'preserved', '/tmp/preserved-project', 17);

            CREATE TABLE meta (
                singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
                schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
                db_generation INTEGER NOT NULL CHECK (db_generation >= 1),
                last_transaction_digest TEXT,
                commit_marker INTEGER NOT NULL DEFAULT 0 CHECK (commit_marker IN (0, 1))
            ) STRICT;
            INSERT INTO meta (singleton, schema_version, db_generation) VALUES (1, 3, 9);

            CREATE TABLE projections (
                runtime_authority TEXT NOT NULL,
                principal TEXT NOT NULL,
                lineage TEXT NOT NULL,
                scope TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                cursor TEXT NOT NULL,
                payload BLOB NOT NULL,
                PRIMARY KEY (runtime_authority, principal, lineage, scope)
            ) STRICT;

            CREATE TABLE event_journal (
                runtime_authority TEXT NOT NULL,
                principal TEXT NOT NULL,
                lineage TEXT NOT NULL,
                scope TEXT NOT NULL,
                event_id TEXT NOT NULL,
                cursor TEXT NOT NULL,
                validated_envelope BLOB NOT NULL,
                digest TEXT NOT NULL,
                PRIMARY KEY (runtime_authority, principal, lineage, scope, event_id)
            ) STRICT;

            CREATE TABLE replay_cursors (
                runtime_authority TEXT NOT NULL,
                principal TEXT NOT NULL,
                lineage TEXT NOT NULL,
                scope TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                applied_cursor TEXT NOT NULL,
                PRIMARY KEY (runtime_authority, principal, lineage, scope)
            ) STRICT;

            PRAGMA user_version = 3;
            ",
        )
        .expect("create v3 schema");
    connection
}

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
fn schema_newer_than_v4_is_rejected_without_rewrite() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let connection = Connection::open(&path).expect("create database");
    connection
        .pragma_update(None, "user_version", 5)
        .expect("set future version");
    drop(connection);

    let Err(error) = LocalStore::open(&path) else {
        panic!("future schema must fail");
    };
    assert!(matches!(error, StoreOpenError::UnsupportedSchema(5)));
    let connection = Connection::open(path).expect("reopen future database");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read future version");
    assert_eq!(version, 5);
}

#[test]
fn transition_atomically_persists_journal_projection_and_checkpoint() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let transition = transition(
        &scope,
        None,
        "event-1",
        "opaque.cursor.1",
        3,
        1,
        event,
        1,
        projection,
    );

    assert_eq!(
        store
            .apply_replay_transition(&transition)
            .expect("apply transition"),
        ReplayApplyOutcome::Applied {
            database_generation: 2
        }
    );

    let checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read checkpoint")
        .expect("stored checkpoint");
    assert_eq!(checkpoint.cursor, "opaque.cursor.1");
    assert_eq!(checkpoint.generation, 3);
    assert_eq!(checkpoint.event_sequence, 1);
    assert_eq!(checkpoint.projection_revision, 1);
    assert_eq!(checkpoint.projection_digest, digest(projection));

    let stored = store
        .conversation_projection(&scope)
        .expect("read projection")
        .expect("stored projection");
    assert_eq!(stored.payload, projection);
    assert_eq!(stored.revision, 1);
    assert_eq!(stored.event_sequence, 1);
    assert_eq!(stored.digest, digest(projection));
}

#[test]
fn exact_duplicate_is_already_applied_without_advancing_database_generation() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let transition = transition(
        &scope,
        None,
        "event-1",
        "opaque.cursor.1",
        3,
        1,
        event,
        1,
        projection,
    );
    store
        .apply_replay_transition(&transition)
        .expect("apply transition");

    assert_eq!(
        store
            .apply_replay_transition(&transition)
            .expect("apply exact duplicate"),
        ReplayApplyOutcome::AlreadyApplied {
            database_generation: 2
        }
    );
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        2
    );
}

#[test]
fn duplicate_rejects_changed_projection_bytes_digest_revision_or_json() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let original = transition(
        &scope,
        None,
        "event-1",
        "opaque.cursor.1",
        3,
        1,
        event,
        1,
        projection,
    );
    store
        .apply_replay_transition(&original)
        .expect("apply original");

    let changed_projection =
        br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#;
    let invalid_projection = br#"{"conversationId":"conversation-1""#;
    let conflicts = [
        ReplayTransition {
            projection_bytes: changed_projection,
            projection_digest: digest(changed_projection),
            ..original.clone()
        },
        ReplayTransition {
            projection_digest: "0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
            ..original.clone()
        },
        ReplayTransition {
            projection_digest: "ABC".into(),
            ..original.clone()
        },
        ReplayTransition {
            projection_revision: 2,
            ..original.clone()
        },
        ReplayTransition {
            projection_bytes: invalid_projection,
            projection_digest: digest(invalid_projection),
            ..original
        },
    ];
    for conflict in &conflicts {
        let error = store
            .apply_replay_transition(conflict)
            .expect_err("changed duplicate projection must conflict");
        assert!(matches!(error, ReplayStoreError::EventIdentityConflict));
    }

    let stored = store
        .conversation_projection(&scope)
        .expect("read projection")
        .expect("stored projection");
    assert_eq!(stored.payload, projection);
    assert_eq!(stored.revision, 1);
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        2
    );
}

#[test]
fn exact_duplicate_does_not_mask_a_corrupt_stored_projection() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let mut store = LocalStore::open(&path).expect("open store");
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        ))
        .expect("apply transition");
    drop(store);
    let connection = Connection::open(&path).expect("open corruptible database");
    connection
        .execute_batch(
            "
            PRAGMA ignore_check_constraints = ON;
            UPDATE projections SET payload = x'7b';
            ",
        )
        .expect("corrupt projection");
    drop(connection);
    let mut store = LocalStore::open(&path).expect("reopen store");

    let error = store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        ))
        .expect_err("corruption must stop duplicate application");
    assert!(matches!(error, ReplayStoreError::CorruptProjectionJson));
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        2
    );
}

#[test]
fn reused_event_id_with_different_identity_rolls_back() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let first = transition(
        &scope,
        None,
        "event-1",
        "opaque.cursor.1",
        3,
        1,
        event,
        1,
        projection,
    );
    store.apply_replay_transition(&first).expect("apply first");
    let conflict = transition(
        &scope,
        None,
        "event-1",
        "opaque.cursor.changed",
        3,
        1,
        br#"{"eventId":"event-1","changed":true}"#,
        1,
        br#"{"conversationId":"conversation-1","messages":["changed"]}"#,
    );

    let error = store
        .apply_replay_transition(&conflict)
        .expect_err("identity conflict");
    assert!(matches!(error, ReplayStoreError::EventIdentityConflict));

    let digest_conflict = ReplayTransition {
        event_digest: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        ..transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        )
    };
    let error = store
        .apply_replay_transition(&digest_conflict)
        .expect_err("digest identity conflict");
    assert!(matches!(error, ReplayStoreError::EventIdentityConflict));

    assert_eq!(
        store
            .replay_checkpoint(&scope)
            .expect("read checkpoint")
            .expect("checkpoint")
            .cursor,
        "opaque.cursor.1"
    );
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        2
    );
}

#[test]
fn rebound_scope_binding_is_not_reported_as_an_exact_duplicate() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        ))
        .expect("apply transition");
    let rebound_scope = ReplayScopeKey {
        binding_digest: OTHER_BINDING_DIGEST.into(),
        ..scope
    };

    let error = store
        .apply_replay_transition(&transition(
            &rebound_scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        ))
        .expect_err("binding mismatch");
    assert!(matches!(error, ReplayStoreError::BindingMismatch));
}

#[test]
fn transition_requires_the_exact_previous_checkpoint_and_contiguous_counters() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        ))
        .expect("apply first");
    let checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read checkpoint")
        .expect("checkpoint");

    let missing_expected = transition(
        &scope,
        None,
        "event-2",
        "opaque.cursor.2",
        3,
        2,
        br#"{"eventId":"event-2","sequence":2}"#,
        2,
        br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#,
    );
    assert!(matches!(
        store.apply_replay_transition(&missing_expected),
        Err(ReplayStoreError::CursorMismatch)
    ));

    let skipped_revision = ReplayTransition {
        projection_revision: 3,
        ..transition(
            &scope,
            Some(&checkpoint),
            "event-2",
            "opaque.cursor.2",
            3,
            2,
            br#"{"eventId":"event-2","sequence":2}"#,
            2,
            br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#,
        )
    };
    assert!(matches!(
        store.apply_replay_transition(&skipped_revision),
        Err(ReplayStoreError::NonContiguousRevision)
    ));

    let skipped_sequence = ReplayTransition {
        event_sequence: 3,
        ..transition(
            &scope,
            Some(&checkpoint),
            "event-2",
            "opaque.cursor.2",
            3,
            2,
            br#"{"eventId":"event-2","sequence":2}"#,
            2,
            br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#,
        )
    };
    assert!(matches!(
        store.apply_replay_transition(&skipped_sequence),
        Err(ReplayStoreError::NonContiguousSequence)
    ));
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        2
    );
}

fn create_applied_store(path: &Path) -> (LocalStore, ReplayScopeKey) {
    let mut store = LocalStore::open(path).expect("open store");
    let scope = scope();
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            br#"{"eventId":"event-1","sequence":1}"#,
            1,
            br#"{"conversationId":"conversation-1","messages":[]}"#,
        ))
        .expect("apply baseline");
    (store, scope)
}

#[test]
fn projection_revision_zero_and_independent_event_cadence_are_valid() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let initial_projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            br#"{"eventId":"event-1","sequence":1}"#,
            0,
            initial_projection,
        ))
        .expect("apply revision-zero projection");
    let checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read checkpoint")
        .expect("checkpoint");
    assert_eq!(checkpoint.event_sequence, 1);
    assert_eq!(checkpoint.projection_revision, 0);

    store
        .apply_replay_transition(&transition(
            &scope,
            Some(&checkpoint),
            "event-2",
            "opaque.cursor.2",
            3,
            2,
            br#"{"eventId":"event-2","sequence":2}"#,
            0,
            initial_projection,
        ))
        .expect("apply event without projection change");
    let checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read second checkpoint")
        .expect("second checkpoint");
    assert_eq!(checkpoint.event_sequence, 2);
    assert_eq!(checkpoint.projection_revision, 0);

    let changed_projection =
        br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#;
    let same_revision_change = transition(
        &scope,
        Some(&checkpoint),
        "event-3",
        "opaque.cursor.3",
        3,
        3,
        br#"{"eventId":"event-3","sequence":3}"#,
        0,
        changed_projection,
    );
    assert!(matches!(
        store.apply_replay_transition(&same_revision_change),
        Err(ReplayStoreError::NonContiguousRevision)
    ));

    store
        .apply_replay_transition(&transition(
            &scope,
            Some(&checkpoint),
            "event-3",
            "opaque.cursor.3",
            3,
            3,
            br#"{"eventId":"event-3","sequence":3}"#,
            1,
            changed_projection,
        ))
        .expect("advance independent projection revision");
    let checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read third checkpoint")
        .expect("third checkpoint");
    assert_eq!(checkpoint.event_sequence, 3);
    assert_eq!(checkpoint.projection_revision, 1);
}

#[test]
fn corrupt_historical_event_digest_stops_reads_and_the_next_transition() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let first_projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            br#"{"eventId":"event-1","sequence":1}"#,
            0,
            first_projection,
        ))
        .expect("apply first");
    let first_checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read first checkpoint")
        .expect("first checkpoint");
    let second_projection =
        br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#;
    store
        .apply_replay_transition(&transition(
            &scope,
            Some(&first_checkpoint),
            "event-2",
            "opaque.cursor.2",
            3,
            2,
            br#"{"eventId":"event-2","sequence":2}"#,
            1,
            second_projection,
        ))
        .expect("apply second");
    let second_checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read second checkpoint")
        .expect("second checkpoint");
    drop(store);

    let connection = Connection::open(&path).expect("open corruptible database");
    connection
        .execute(
            "UPDATE event_journal SET validated_event = ?1 WHERE event_sequence = 1",
            [b"{\"eventId\":\"event-1\",\"corrupt\":true}".as_slice()],
        )
        .expect("corrupt historical event bytes");
    drop(connection);

    let mut store = LocalStore::open(&path).expect("reopen store");
    assert!(matches!(
        store.replay_checkpoint(&scope),
        Err(ReplayStoreError::EventDigestMismatch)
    ));
    assert!(matches!(
        store.conversation_projection(&scope),
        Err(ReplayStoreError::EventDigestMismatch)
    ));
    let error = store
        .apply_replay_transition(&transition(
            &scope,
            Some(&second_checkpoint),
            "event-3",
            "opaque.cursor.3",
            3,
            3,
            br#"{"eventId":"event-3","sequence":3}"#,
            1,
            second_projection,
        ))
        .expect_err("historical corruption must stop cursor advance");
    assert!(matches!(error, ReplayStoreError::EventDigestMismatch));
    drop(store);

    let connection = Connection::open(path).expect("inspect preserved state");
    let (journal_count, cursor, database_generation): (i64, String, i64) = connection
        .query_row(
            "
            SELECT COUNT(*), replay_cursors.applied_cursor, meta.db_generation
            FROM event_journal
            CROSS JOIN replay_cursors
            CROSS JOIN meta
            WHERE meta.singleton = 1
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read preserved state");
    assert_eq!(journal_count, 2);
    assert_eq!(cursor, "opaque.cursor.2");
    assert_eq!(database_generation, 3);
}

#[test]
fn corrupt_stored_event_digest_shape_fails_closed() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let (store, scope) = create_applied_store(&path);
    drop(store);
    let connection = Connection::open(&path).expect("open corruptible database");
    connection
        .execute_batch(
            "
            PRAGMA ignore_check_constraints = ON;
            UPDATE event_journal SET event_digest = 'ABC' WHERE event_sequence = 1;
            ",
        )
        .expect("corrupt event digest shape");
    drop(connection);

    let store = LocalStore::open(&path).expect("reopen store");
    assert!(matches!(
        store.replay_checkpoint(&scope),
        Err(ReplayStoreError::InvalidDigest)
    ));
}

#[test]
fn projection_reads_fail_closed_for_corrupt_json_digest_binding_and_revision() {
    for (label, mutation, expected) in [
        (
            "json",
            "PRAGMA ignore_check_constraints = ON;
             UPDATE projections SET payload = x'7b';",
            "corrupt",
        ),
        (
            "digest",
            "UPDATE projections
             SET projection_digest =
               '0000000000000000000000000000000000000000000000000000000000000000';",
            "digest",
        ),
        (
            "binding",
            "UPDATE projections
             SET binding_digest =
               '2222222222222222222222222222222222222222222222222222222222222222';",
            "binding",
        ),
        (
            "revision",
            "UPDATE projections SET projection_revision = projection_revision + 2;
             UPDATE replay_cursors SET projection_revision = projection_revision + 2;",
            "revision",
        ),
    ] {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join(format!("{label}.sqlite3"));
        let (store, scope) = create_applied_store(&path);
        drop(store);
        let connection = Connection::open(&path).expect("open corruptible database");
        connection
            .execute_batch(mutation)
            .expect("corrupt projection");
        drop(connection);
        let store = LocalStore::open(&path).expect("reopen store");

        let error = store
            .conversation_projection(&scope)
            .expect_err("corrupt projection must fail closed");
        match expected {
            "corrupt" => assert!(matches!(error, ReplayStoreError::CorruptProjectionJson)),
            "digest" => assert!(matches!(error, ReplayStoreError::ProjectionDigestMismatch)),
            "binding" => assert!(matches!(error, ReplayStoreError::BindingMismatch)),
            "revision" => assert!(matches!(error, ReplayStoreError::NonContiguousRevision)),
            _ => unreachable!(),
        }
    }
}

#[test]
fn transition_rejects_empty_cursor_and_invalid_digests_before_mutation() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let mut invalid_cursor = transition(
        &scope,
        None,
        "event-1",
        "",
        3,
        1,
        br#"{"eventId":"event-1"}"#,
        1,
        br#"{"conversationId":"conversation-1"}"#,
    );
    assert!(matches!(
        store.apply_replay_transition(&invalid_cursor),
        Err(ReplayStoreError::EmptyCursor)
    ));

    invalid_cursor.cursor = "opaque";
    invalid_cursor.event_digest = "ABC".into();
    assert!(matches!(
        store.apply_replay_transition(&invalid_cursor),
        Err(ReplayStoreError::InvalidDigest)
    ));

    let rebound_scope = ReplayScopeKey {
        binding_digest: OTHER_BINDING_DIGEST.into(),
        ..scope
    };
    assert!(
        store
            .replay_checkpoint(&rebound_scope)
            .expect("empty rebound scope")
            .is_none()
    );
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        1
    );
}

#[test]
fn historical_concurrent_duplicate_is_confirmed_without_mutation() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let (mut store, scope) = create_applied_store(&path);
    let first_checkpoint = store
        .replay_checkpoint(&scope)
        .expect("checkpoint")
        .expect("first checkpoint");
    store
        .apply_replay_transition(&transition(
            &scope,
            Some(&first_checkpoint),
            "event-2",
            "opaque.cursor.2",
            3,
            2,
            br#"{"eventId":"event-2","sequence":2}"#,
            2,
            br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#,
        ))
        .expect("apply second");
    let generation_before = store
        .diagnostics()
        .expect("diagnostics")
        .database_generation;
    let event_bytes = br#"{"eventId":"event-1","sequence":1}"#;
    let event_digest = digest(event_bytes);
    let identity = AppliedReplayEvent {
        scope: &scope,
        event_id: "event-1",
        cursor: "opaque.cursor.1",
        generation: 3,
        event_sequence: 1,
        event_bytes,
        event_digest: &event_digest,
    };

    assert_eq!(
        store
            .confirm_replay_event_applied(&identity)
            .expect("confirm historical duplicate"),
        ReplayApplyOutcome::AlreadyApplied {
            database_generation: generation_before
        }
    );
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        generation_before
    );

    let changed = AppliedReplayEvent {
        cursor: "opaque.cursor.changed",
        ..identity
    };
    assert!(matches!(
        store.confirm_replay_event_applied(&changed),
        Err(ReplayStoreError::EventIdentityConflict)
    ));
}
