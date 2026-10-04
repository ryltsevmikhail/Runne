#[test]
fn v59_adds_remote_terminal_fact_settlement_receipt() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 58).unwrap();
    apply_migrations_internal(&connection, 59).unwrap();
    assert_eq!(schema_marker(&connection), 59);
    assert!(v42_structure_matches(&connection, true).unwrap());
    assert!(v43_matches(&connection, 59).unwrap());
    assert!(v44_matches(&connection, 59).unwrap());
    assert!(v45_matches(&connection, 59).unwrap());
    assert!(v46_matches(&connection, 59).unwrap());
    assert!(v47_matches(&connection, 59).unwrap());
    assert!(v48_matches(&connection, 59).unwrap());
    assert!(v49_matches(&connection, 59).unwrap());
    assert!(v50_base_matches(&connection, 59).unwrap());
    assert!(v51_base_matches(&connection, 59).unwrap());
    assert!(v52_base_matches(&connection, 59).unwrap());
    assert!(v53_base_matches(&connection, 59).unwrap());
    assert!(v54_matches(&connection, 59).unwrap());
    assert!(v55_matches(&connection, 59).unwrap());
    assert!(v56_matches(&connection, 59).unwrap());
    assert!(v57_matches(&connection, 59).unwrap());
    assert!(v58_matches(&connection, 59).unwrap());
    assert!(v59_matches(&connection, 59).unwrap());
    let ddl: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_remote_terminal_settlements'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    for required in [
        "source_kind INTEGER NOT NULL CHECK(source_kind=2)",
        "conversation_id BLOB NOT NULL CHECK(length(conversation_id)=16 AND conversation_id!=zeroblob(16))",
        "writer_fencing_token INTEGER NOT NULL CHECK(writer_fencing_token>0)",
        "begin_event_digest BLOB NOT NULL CHECK(length(begin_event_digest)=32 AND begin_event_digest!=zeroblob(32))",
        "terminal_status INTEGER NOT NULL CHECK(terminal_status IN (1,2,3,5))",
        "publication_disposition INTEGER NOT NULL CHECK(publication_disposition BETWEEN 0 AND 5)",
        "FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_remote_terminal_artifacts",
    ] {
        assert!(ddl.contains(required), "missing DDL contract: {required}");
    }
}

#[test]
fn v59_readiness_rejects_missing_append_only_guards() {
    for trigger in [
        "provider_remote_terminal_settlements_identity_immutable",
        "provider_remote_terminal_settlements_state_transition",
        "provider_remote_terminal_settlements_no_delete",
        "schema_v12_fence_provider_remote_terminal_settlements_insert",
        "schema_v12_fence_provider_remote_terminal_settlements_update",
        "schema_v12_fence_provider_remote_terminal_settlements_delete",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 59).unwrap();
        connection
            .execute_batch(&format!("DROP TRIGGER {trigger}"))
            .unwrap();
        assert!(!v59_matches(&connection, 59).unwrap(), "{trigger}");
    }
}

#[test]
fn v59_keeps_known_usage_and_unsettled_application_facts_immutable() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 59).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    let insert = |attempt: &[u8; 16], state: i64| {
        connection.execute(
            "INSERT INTO provider_remote_terminal_settlements(
                dispatch_attempt_id,taskrun_id,taskrun_attempt_id,conversation_id,
                writer_owner_principal,writer_fencing_token,begin_command_id,generation_id,
                begin_event_digest,source_kind,terminal_status,publication_disposition,
                request_digest,response_id_digest,artifact_digest,profile_digest,
                pricing_revision_digest,runtime_authority_id,database_generation,
                runtime_generation,fencing_token,expected_taskrun_version,settlement_state,
                input_tokens,output_tokens,cached_input_tokens,reasoning_output_tokens,created_at
             ) VALUES(?1,?2,?3,?4,'owner',1,?5,?6,?7,2,1,0,?8,?9,?10,?11,?12,?13,1,1,1,1,?14,8,3,0,0,1)",
            rusqlite::params![
                attempt.as_slice(), &[2_u8; 16][..], &[3_u8; 16][..], &[4_u8; 16][..],
                &[5_u8; 16][..], &[6_u8; 16][..], &[7_u8; 32][..], &[8_u8; 32][..], &[9_u8; 32][..],
                &[10_u8; 32][..], &[11_u8; 32][..], &[12_u8; 32][..], &[17_u8; 16][..], state,
            ],
        ).unwrap();
    };
    insert(&[1; 16], 1);
    assert!(
        connection
            .execute(
                "UPDATE provider_remote_terminal_settlements SET settlement_state=2,input_tokens=9,
             charge_micros=3,currency='USD',settlement_digest=?2 WHERE dispatch_attempt_id=?1",
                rusqlite::params![&[1_u8; 16][..], &[13_u8; 32][..]],
            )
            .is_err()
    );
    connection
        .execute(
            "UPDATE provider_remote_terminal_settlements SET settlement_state=2,
             charge_micros=3,currency='USD',settlement_digest=?2 WHERE dispatch_attempt_id=?1",
            rusqlite::params![&[1_u8; 16][..], &[13_u8; 32][..]],
        )
        .unwrap();
    assert!(connection.execute(
        "UPDATE provider_remote_terminal_settlements SET settlement_state=4,output_tokens=4,
             application_receipt_digest=?2 WHERE dispatch_attempt_id=?1",
        rusqlite::params![&[1_u8; 16][..], &[14_u8; 32][..]],
    ).is_err());
    connection
        .execute(
            "UPDATE provider_remote_terminal_settlements SET settlement_state=4,
             application_receipt_digest=?2 WHERE dispatch_attempt_id=?1",
            rusqlite::params![&[1_u8; 16][..], &[14_u8; 32][..]],
        )
        .unwrap();

    insert(&[15_u8; 16], 1);
    connection
        .execute(
            "UPDATE provider_remote_terminal_settlements SET settlement_state=5,
             application_receipt_digest=?2 WHERE dispatch_attempt_id=?1",
            rusqlite::params![&[15_u8; 16][..], &[16_u8; 32][..]],
        )
        .unwrap();
    let state: (i64, i64, Option<i64>) = connection.query_row(
        "SELECT settlement_state,input_tokens,charge_micros FROM provider_remote_terminal_settlements
         WHERE dispatch_attempt_id=?1",
        [&[15_u8; 16][..],],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();
    assert_eq!(state, (5, 8, None));

    insert(&[18_u8; 16], 1);
    connection
        .execute(
            "UPDATE provider_remote_terminal_settlements SET settlement_state=3
         WHERE dispatch_attempt_id=?1",
            [&[18_u8; 16][..]],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE provider_remote_terminal_settlements SET settlement_state=5,
             application_receipt_digest=?2 WHERE dispatch_attempt_id=?1",
            rusqlite::params![&[18_u8; 16][..], &[19_u8; 32][..]],
        )
        .unwrap();
    let audited: (i64, i64, Option<i64>) = connection.query_row(
        "SELECT settlement_state,input_tokens,charge_micros FROM provider_remote_terminal_settlements
         WHERE dispatch_attempt_id=?1",
        [&[18_u8; 16][..]],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();
    assert_eq!(audited, (5, 8, None));
}

#[cfg(unix)]
#[test]
fn v59_validated_reopen_after_managed_v58_upgrade() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = daemon.join("remote-terminal.db");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations_internal(&connection, 58).unwrap();
    drop(connection);

    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    drop(connection);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let reopened =
        reopen_managed_connection_validated(&path, ConnectionMode::ValidatedReopen, |connection| {
            assert_eq!(schema_marker(connection), CURRENT_SCHEMA_VERSION);
            assert!(v63_matches(connection, CURRENT_SCHEMA_VERSION)?);
            Ok(())
        })
        .unwrap();
    assert_eq!(schema_marker(&reopened), CURRENT_SCHEMA_VERSION);
}
