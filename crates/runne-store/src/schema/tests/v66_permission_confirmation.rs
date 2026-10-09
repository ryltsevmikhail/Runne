#[test]
fn v66_invalidates_only_pending_v1_challenges_and_preserves_history() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 65).unwrap();
    assert!(v65_matches(&connection, 65).unwrap());
    insert_v65_challenge(&connection, 1);
    insert_v65_challenge(&connection, 2);
    insert_v65_challenge(&connection, 3);
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
    connection
        .execute(
            "INSERT INTO permission_mode_command_receipts (
           command_id,runtime_authority_id,principal_id,workspace_id,project_id,idempotency_key,
           intent_digest,selected_mode,preset_version,authorization_revision,managed_policy_version,
           managed_policy_digest,expires_at_unix_ms,history_projection,committed_at_unix_ms
         ) VALUES (zeroblob(16),'authority','principal',zeroblob(16),zeroblob(16),'receipt',
           zeroblob(32),1,1,1,0,zeroblob(32),NULL,x'01',1)",
            [],
        )
        .unwrap();

    apply_migrations_internal(&connection, 66).unwrap();
    assert!(
        v42_structure_matches(&connection, true).unwrap(),
        "v42 structure"
    );
    assert!(
        table_sql_matches_migration(&connection, "permission_mode_selections", MIGRATION_V65)
            .unwrap(),
        "selection ddl"
    );
    assert!(
        table_sql_matches_migration(
            &connection,
            "taskrun_tool_permission_admissions",
            MIGRATION_V65
        )
        .unwrap(),
        "admission ddl"
    );
    assert!(
        table_sql_matches_migration(
            &connection,
            "permission_mode_command_receipts",
            MIGRATION_V65
        )
        .unwrap(),
        "receipt ddl"
    );
    assert!(
        table_sql_matches_migration(
            &connection,
            "permission_mode_native_challenges",
            MIGRATION_V66
        )
        .unwrap(),
        "challenge ddl"
    );
    assert!(
        index_matches(
            &connection,
            "idx_permission_mode_challenges_pending",
            "permission_mode_native_challenges",
            &[
                "runtime_authority_id",
                "principal_id",
                "workspace_id",
                "state",
                "expires_at_unix_ms"
            ]
        )
        .unwrap(),
        "challenge index"
    );
    assert!(v66_matches(&connection, 66).unwrap());
    let states: Vec<(i64, i64, i64)> = connection
        .prepare("SELECT state,confirmation_phase,digest_version FROM permission_mode_native_challenges ORDER BY command_id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(states, [(3, 3, 1), (2, 2, 1), (3, 3, 1)]);
    let preserved_consumption: (Option<Vec<u8>>, Option<i64>) = connection
        .query_row(
            "SELECT proof_identifier,consumed_at_unix_ms
             FROM permission_mode_native_challenges WHERE state=2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(preserved_consumption, (Some(vec![9; 32]), Some(1)));
    let legacy_sessions: (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),SUM(protected_session_id IS NULL)
             FROM permission_mode_native_challenges WHERE digest_version=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(legacy_sessions, (3, 3));
    let preserved: (i64, i64, i64, i64, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM permission_mode_selections),
                (SELECT selected_mode FROM permission_mode_selections),
                (SELECT authorization_revision FROM permission_mode_selections),
                (SELECT COUNT(*) FROM permission_mode_command_receipts),
                (SELECT history_projection FROM permission_mode_command_receipts)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(preserved, (1, 1, 1, 1, vec![1]));
    drop(connection);
}

#[test]
fn v66_challenge_binding_fields_are_immutable_and_terminal_phases_are_distinct() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 66).unwrap();
    assert!(v66_matches(&connection, 66).unwrap());
    let sql = String::from(
        "INSERT INTO permission_mode_native_challenges (
           challenge_id,nonce,challenge_binding_digest,request_digest,command_id,
           runtime_authority_id,principal_id,workspace_id,project_id,workspace_version,
           idempotency_key,store_authority_id,store_lineage_id,expected_authorization_revision,
           preset_version,managed_policy_instance_epoch,managed_policy_revision,managed_policy_status,
           managed_deny_mask,managed_policy_digest,launch_authority_id,desktop_host_instance_id,
           daemon_instance_id,launch_generation,native_key_epoch,protected_session_id,native_warning_version,
           issued_at_unix_ms,expires_at_unix_ms,requested_mode,digest_version,public_request_digest,
           state,proof_identifier,consumed_at_unix_ms,confirmation_phase
         ) VALUES (zeroblob(16),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(16),
           'authority','principal',zeroblob(16),zeroblob(16),1,'key',zeroblob(16),
           '00000000-0000-0000-0000-000000000000',0,1,1,0,1,0,zeroblob(32),
           zeroblob(16),zeroblob(16),zeroblob(16),1,1,x'018f2e3a700070008000000000000001',1,1,2,1,2,zeroblob(32),1,NULL,NULL,1)",
    );
    // Nonzero identities and digests satisfy the V2 row's exact shape.
    let sql = sql
        .replace("zeroblob(16)", "x'01010101010101010101010101010101'")
        .replace(
            "zeroblob(32)",
            "x'0202020202020202020202020202020202020202020202020202020202020202'",
        );
    let malformed_connection = Connection::open_in_memory().unwrap();
    apply_migrations(&malformed_connection).unwrap();
    let malformed_sql = sql.replace(
        "x'018f2e3a700070008000000000000001'",
        "x'018f2e3a700060008000000000000001'",
    );
    assert!(malformed_connection.execute_batch(&malformed_sql).is_err());
    let null_proof_sql = sql.replace(
        "x'0202020202020202020202020202020202020202020202020202020202020202',1,NULL,NULL,1)",
        "x'0202020202020202020202020202020202020202020202020202020202020202',2,NULL,1,2)",
    );
    assert!(malformed_connection.execute_batch(&null_proof_sql).is_err());
    connection.execute_batch(&sql).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE permission_mode_native_challenges SET requested_mode=2",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE permission_mode_native_challenges SET protected_session_id=x'028f2e3a700070008000000000000001'",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE permission_mode_native_challenges
                 SET state=2,confirmation_phase=2,proof_identifier=NULL,consumed_at_unix_ms=1",
                [],
            )
            .is_err()
    );
    connection
        .execute(
            "UPDATE permission_mode_native_challenges SET state=3,confirmation_phase=4",
            [],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                "UPDATE permission_mode_native_challenges SET state=3,confirmation_phase=3",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM permission_mode_native_challenges", [])
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE permission_mode_native_challenges SET state=3,confirmation_phase=5",
                [],
            )
            .is_err()
    );
}

#[test]
fn v66_rejects_tampered_markers_and_schema_guards() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 66).unwrap();
    assert_eq!(schema_marker(&connection), 66);
    assert!(v64_matches(&connection, 66).unwrap());
    assert!(v66_matches(&connection, 66).unwrap());

    connection
        .execute("UPDATE schema_version SET version=67 WHERE version=66", [])
        .unwrap();
    assert!(!v64_matches(&connection, 67).unwrap());
    assert!(!v66_matches(&connection, 66).unwrap());
    assert!(classify_schema_version(&connection).is_err());

    let schema = Connection::open_in_memory().unwrap();
    apply_migrations(&schema).unwrap();
    schema
        .execute_batch("DROP TRIGGER permission_mode_native_confirmation_v2_update")
        .unwrap();
    assert!(!v66_matches(&schema, 66).unwrap());
}

#[test]
fn v66_accepts_the_exact_omitted_v19_lineage_marker() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 66).unwrap();
    connection
        .execute("DELETE FROM schema_version WHERE version=19", [])
        .unwrap();
    let marker: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT MAX(version),MIN(version),COUNT(*),SUM(version) FROM schema_version",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(marker, (66, 1, 65, 2192));
    assert!(v64_matches(&connection, 66).unwrap());
    assert!(v66_matches(&connection, 66).unwrap());
}
