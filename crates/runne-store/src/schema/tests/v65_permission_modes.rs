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
    apply_migrations_internal(&connection, 65).unwrap();
    assert!(v65_matches(&connection, 65).unwrap());
    connection
        .execute_batch("DROP TRIGGER permission_mode_native_challenge_update")
        .unwrap();
    assert!(!v65_matches(&connection, 65).unwrap());
}

#[test]
fn v65_startup_rejects_unrecognized_permission_mode_schema_drift() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 65).unwrap();
    connection
        .execute_batch("DROP INDEX idx_permission_mode_challenges_pending")
        .unwrap();
    assert!(classify_schema_version(&connection).is_err());
}

fn insert_v65_challenge(connection: &Connection, state: i64) {
    let challenge_id = [state as u8 + 1; 16];
    let nonce = [state as u8 + 4; 32];
    let digest = [state as u8 + 7; 32];
    let proof = (state == 2).then_some(digest.as_slice());
    let consumed = (state == 2).then_some(1_i64);
    connection
        .execute(
            "INSERT INTO permission_mode_native_challenges (
               challenge_id,nonce,challenge_binding_digest,request_digest,command_id,
               runtime_authority_id,principal_id,workspace_id,project_id,workspace_version,
               idempotency_key,store_authority_id,store_lineage_id,expected_authorization_revision,
               preset_version,managed_policy_instance_epoch,managed_policy_revision,
               managed_policy_status,managed_deny_mask,managed_policy_digest,mode_expires_at_unix_ms,
               launch_authority_id,desktop_host_instance_id,daemon_instance_id,launch_generation,
               native_key_epoch,native_warning_version,issued_at_unix_ms,expires_at_unix_ms,
               state,proof_identifier,consumed_at_unix_ms
             ) VALUES (?1,?2,?3,zeroblob(32),?4,'authority','principal',zeroblob(16),zeroblob(16),1,
               ?5,x'01010101010101010101010101010101','00000000-0000-0000-0000-000000000000',0,1,1,0,1,0,zeroblob(32),NULL,
               ?6,?7,?8,1,1,1,1,2,?9,?10,?11)",
            params![
                challenge_id.as_slice(),
                nonce.as_slice(),
                digest.as_slice(),
                [state as u8 + 10; 16].as_slice(),
                format!("key-{state}"),
                [0x31_u8; 16].as_slice(),
                [0x32_u8; 16].as_slice(),
                [0x33_u8; 16].as_slice(),
                state,
                proof,
                consumed,
            ],
        )
        .unwrap();
}
