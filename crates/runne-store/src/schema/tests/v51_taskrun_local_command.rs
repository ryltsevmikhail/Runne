#[test]
fn v51_local_command_attempt_schema_is_strict_and_append_only() {
    let path =
        std::env::temp_dir().join(format!("runne-v51-local-{}.sqlite", uuid::Uuid::new_v4()));
    let connection = Connection::open(&path).unwrap();
    apply_migrations_internal(&connection, 51).unwrap();
    assert_eq!(schema_marker(&connection), 51);
    assert!(v51_matches(&connection, 51).unwrap());

    let ddl: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='taskrun_local_command_attempts'",
        [], |row| row.get(0),
    ).unwrap();
    assert!(ddl.contains("length(command_digest)=32"));
    assert!(ddl.contains("length(managed_area_identity)=100"));
    assert!(ddl.contains("length(stdout)<=65536"));
    drop(connection);

    let reopened = Connection::open(&path).unwrap();
    assert!(v51_matches(&reopened, 51).unwrap(), "V51 raw reopen DDL");
    apply_migrations_internal(&reopened, 51).unwrap();
    assert!(
        v51_matches(&reopened, 51).unwrap(),
        "V51 reopens with exact DDL"
    );

    reopened
        .execute("DROP TRIGGER taskrun_local_command_state_transition", [])
        .unwrap();
    assert!(
        !v51_matches(&reopened, 51).unwrap(),
        "tampered transition trigger is rejected"
    );
    drop(reopened);
    let _ = std::fs::remove_file(path);
}

#[test]
fn v51_local_command_writer_occupation_is_unique_until_known_terminal() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 51).unwrap();
    let insert = "INSERT INTO taskrun_local_command_attempts
        (taskrun_id,conversation_id,workspace_id,command_digest,state,updated_at)
        VALUES (?1,?2,?3,?4,'preflight',1)";
    connection
        .execute(
            insert,
            rusqlite::params![[1_u8; 16], [2_u8; 16], [3_u8; 16], [4_u8; 32]],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                insert,
                rusqlite::params![[5_u8; 16], [2_u8; 16], [3_u8; 16], [6_u8; 32]]
            )
            .is_err()
    );
    connection.execute("UPDATE taskrun_local_command_attempts SET state='no_effect_terminal' WHERE taskrun_id=?1", [[1_u8;16]]).unwrap();
    connection
        .execute(
            insert,
            rusqlite::params![[5_u8; 16], [2_u8; 16], [3_u8; 16], [6_u8; 32]],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                "DELETE FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
                [[1_u8; 16]]
            )
            .is_err()
    );
}

#[test]
fn v51_local_command_pre_effect_states_can_be_terminalized_safely() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 51).unwrap();
    for (index, initial) in ["preflight", "approval_pending", "approved"]
        .into_iter()
        .enumerate()
    {
        let taskrun_id = [index as u8 + 1; 16];
        connection
            .execute(
                "INSERT INTO taskrun_local_command_attempts
             (taskrun_id,conversation_id,workspace_id,command_digest,state,updated_at)
             VALUES (?1,?2,?3,?4,?5,1)",
                rusqlite::params![taskrun_id, [9_u8; 16], [8_u8; 16], [7_u8; 32], initial],
            )
            .unwrap();
        connection.execute(
            "UPDATE taskrun_local_command_attempts SET state='no_effect_terminal' WHERE taskrun_id=?1",
            [taskrun_id],
        ).unwrap();
    }
    assert!(v51_matches(&connection, 51).unwrap());
}

#[test]
fn v51_local_command_binding_cannot_be_partially_cleared() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 51).unwrap();
    connection
        .execute(
            "INSERT INTO taskrun_local_command_attempts
         (taskrun_id,conversation_id,workspace_id,attempt_id,node_id,node_epoch,fence,
          command_digest,managed_area_identity,state,updated_at)
         VALUES (?1,?2,?3,?4,?5,1,1,?6,?7,'launch_intent',1)",
            rusqlite::params![
                [1_u8; 16],
                [2_u8; 16],
                [3_u8; 16],
                [4_u8; 16],
                [5_u8; 16],
                [6_u8; 32],
                [7_u8; 100]
            ],
        )
        .unwrap();
    for field in ["attempt_id", "fence", "managed_area_identity"] {
        let sql =
            format!("UPDATE taskrun_local_command_attempts SET {field}=NULL WHERE taskrun_id=?1");
        assert!(
            connection.execute(&sql, [[1_u8; 16]]).is_err(),
            "{field} cannot be cleared"
        );
    }
    assert!(
        connection
            .execute(
                "INSERT INTO taskrun_local_command_attempts
         (taskrun_id,conversation_id,workspace_id,attempt_id,command_digest,state,updated_at)
         VALUES (?1,?2,?3,?4,?5,'launch_intent',1)",
                rusqlite::params![[8_u8; 16], [2_u8; 16], [3_u8; 16], [9_u8; 16], [10_u8; 32]],
            )
            .is_err(),
        "partial process binding is invalid"
    );
}

#[test]
fn v51_local_command_approval_binding_keeps_both_root_versions_and_policy_versions() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 51).unwrap();
    connection
        .execute(
            "INSERT INTO taskrun_local_command_attempts
         (taskrun_id,conversation_id,workspace_id,attempt_id,node_id,node_epoch,fence,
          command_digest,executable_digest,workspace_version,admitted_root_version,
          admitted_root_identity,trust_epoch,trust_revision,source_policy_version,
          command_policy_version,approval_id,state,updated_at)
         VALUES (?1,?2,?3,?4,?5,1,1,?6,?7,9,7,?8,2,3,2,1,?9,'approved',1)",
            rusqlite::params![
                [1_u8; 16], [2_u8; 16], [3_u8; 16], [4_u8; 16], [5_u8; 16], [6_u8; 32], [7_u8; 32],
                [8_u8; 32], [9_u8; 16]
            ],
        )
        .unwrap();
    for field in [
        "workspace_version",
        "admitted_root_version",
        "admitted_root_identity",
        "trust_epoch",
        "trust_revision",
        "source_policy_version",
        "command_policy_version",
        "executable_digest",
    ] {
        let sql =
            format!("UPDATE taskrun_local_command_attempts SET {field}=NULL WHERE taskrun_id=?1");
        assert!(
            connection.execute(&sql, [[1_u8; 16]]).is_err(),
            "{field} binding is immutable"
        );
    }
    assert!(v51_matches(&connection, 51).unwrap());
}
