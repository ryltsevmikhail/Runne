#[test]
fn v69_migrates_both_authorized_marker_histories_and_reopens() {
    for full in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("context.sqlite");
        let connection = Connection::open(&path).unwrap();
        if full {
            apply_migrations_internal(&connection, 19).unwrap();
        }
        apply_migrations_internal(&connection, 68).unwrap();
        assert!(v68_matches(&connection, 68).unwrap());
        apply_migrations_internal(&connection, 69).unwrap();
        assert!(v69_matches(&connection, 69).unwrap());
        assert!(!v68_matches(&connection, 68).unwrap());
        let marker: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT MAX(version),MIN(version),COUNT(*),SUM(version) FROM schema_version",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            marker,
            if full {
                (69, 1, 69, 2415)
            } else {
                (69, 1, 68, 2396)
            }
        );
        let columns: Vec<(String, String, i64, Option<String>)> = connection
            .prepare("PRAGMA table_info(x2_permission_bindings)")
            .unwrap()
            .query_map([], |r| Ok((r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .unwrap()
            .collect::<SqliteResult<_>>()
            .unwrap();
        assert_eq!(
            &columns[12..],
            &[
                ("retained_context".into(), "BLOB".into(), 0, None),
                ("retained_context_digest".into(), "BLOB".into(), 0, None)
            ]
        );
        drop(connection);
        let reopened = Connection::open(&path).unwrap();
        assert!(v69_matches(&reopened, 69).unwrap());
        assert!(classify_existing_connection(&reopened).is_ok());
    }
}

#[test]
fn v69_rejects_extra_altered_or_missing_binding_triggers_and_marker_drift() {
    for mutation in [
        "CREATE TRIGGER extra_binding_trigger BEFORE INSERT ON x2_permission_bindings BEGIN SELECT 1; END",
        "DROP TRIGGER x2_permission_bindings_context_pair_guard",
        "DROP TRIGGER x2_permission_bindings_immutable",
        "DROP TRIGGER x2_permission_bindings_context_pair_guard; CREATE TRIGGER x2_permission_bindings_context_pair_guard BEFORE INSERT ON x2_permission_bindings BEGIN SELECT 1; END",
        "DELETE FROM schema_version WHERE version=20; INSERT INTO schema_version(version) VALUES(0)",
        "INSERT INTO schema_version(version) VALUES(70)",
        "ALTER TABLE schema_version ADD COLUMN unknown INTEGER",
    ] {
        let c = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&c, 69).unwrap();
        assert!(v69_matches(&c, 69).unwrap());
        c.execute_batch(mutation).unwrap();
        assert!(!v69_matches(&c, 69).unwrap(), "{mutation}");
        assert!(classify_existing_connection(&c).is_err(), "{mutation}");
    }
}

#[test]
fn v69_precondition_and_failed_postcheck_leave_owned_v68_unchanged() {
    let c = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&c, 68).unwrap();
    c.execute_batch("CREATE TRIGGER reject_context_marker BEFORE INSERT ON schema_version WHEN NEW.version=69 BEGIN SELECT RAISE(ABORT,'owned test marker failure'); END").unwrap();
    assert!(apply_v69_migration(&c).is_err());
    assert_eq!(schema_marker(&c), 68);
    let n:i64=c.query_row("SELECT COUNT(*) FROM pragma_table_info('x2_permission_bindings') WHERE name='retained_context'",[],|r|r.get(0)).unwrap();
    assert_eq!(n, 0);
    c.execute_batch("DROP TRIGGER reject_context_marker")
        .unwrap();
    apply_v69_migration(&c).unwrap();
    assert!(v69_matches(&c, 69).unwrap());
}

#[test]
fn v69_pair_constraints_are_exact_in_isolated_owned_ddl_fixture() {
    // Schema-only fake rows, not valid runtime captures or authority evidence.
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch("CREATE TABLE taskrun_local_command_attempts(taskrun_id BLOB PRIMARY KEY); CREATE TABLE taskrun_assignments(taskrun_id BLOB,fence INTEGER,PRIMARY KEY(taskrun_id,fence));").unwrap();
    c.execute_batch(V69_BINDING_DDL).unwrap();
    c.execute_batch(V69_PAIR_TRIGGER.1).unwrap();
    let insert = "INSERT INTO x2_permission_bindings(taskrun_id,attempt_id,fence,invocation_id,binding_digest,codec_version,binding,native_owner_id,native_owner_generation,selection_managed_policy_version,selection_managed_policy_digest,captured_at,retained_context,retained_context_digest) VALUES(?1,?1,1,?1,?2,1,X'01',?1,?3,0,?2,1,?4,?5)";
    use rusqlite::types::Value;
    for (index, (context, digest, accepted)) in [
        (Value::Null, Value::Null, true),
        (Value::Blob(vec![1]), Value::Blob(vec![2; 32]), true),
        (Value::Blob(vec![1]), Value::Null, false),
        (Value::Null, Value::Blob(vec![2; 32]), false),
        (Value::Text("x".into()), Value::Blob(vec![2; 32]), false),
        (Value::Blob(vec![]), Value::Blob(vec![2; 32]), false),
        (Value::Blob(vec![1]), Value::Text("x".repeat(32)), false),
        (Value::Blob(vec![1]), Value::Blob(vec![2; 31]), false),
        (
            Value::Blob(vec![1; 1048577]),
            Value::Blob(vec![2; 32]),
            false,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let id = [u8::try_from(index + 1).unwrap(); 16];
        c.execute(
            "INSERT INTO taskrun_local_command_attempts VALUES(?1)",
            [id],
        )
        .unwrap();
        c.execute("INSERT INTO taskrun_assignments VALUES(?1,1)", [id])
            .unwrap();
        let result = c.execute(
            insert,
            rusqlite::params![id, [2u8; 32], [3u8; 8], context, digest],
        );
        assert_eq!(result.is_ok(), accepted, "pair {index}: {result:?}");
    }
    c.execute_batch(V68_SIDECAR_TRIGGERS[0].1).unwrap();
    c.execute_batch(V68_SIDECAR_TRIGGERS[1].1).unwrap();
    assert!(
        c.execute(
            "UPDATE x2_permission_bindings SET retained_context=NULL",
            []
        )
        .is_err()
    );
    assert!(c.execute("DELETE FROM x2_permission_bindings", []).is_err());
}
