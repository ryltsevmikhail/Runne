#[test]
fn v52_profile_grant_tables_are_strict_append_only_and_reopenable() {
    let path = std::env::temp_dir().join(format!(
        "runne-v52-profile-grant-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let connection = Connection::open(&path).unwrap();
    apply_migrations_internal(&connection, 52).unwrap();
    assert_eq!(schema_marker(&connection), 52);
    assert!(
        table_sql_matches_migration(
            &connection,
            "provider_secondary_profile_bindings",
            MIGRATION_V52
        )
        .unwrap()
    );
    assert!(
        table_sql_matches_migration(
            &connection,
            "provider_secondary_profile_grants",
            MIGRATION_V52
        )
        .unwrap()
    );
    assert!(
        table_sql_matches_migration(
            &connection,
            "provider_secondary_profile_attempts",
            MIGRATION_V52
        )
        .unwrap()
    );
    assert!(v52_matches(&connection, 52).unwrap());
    drop(connection);

    let reopened = Connection::open(&path).unwrap();
    assert!(v52_matches(&reopened, 52).unwrap(), "V52 raw reopen DDL");
    reopened
        .execute(
            "DROP TRIGGER provider_secondary_profile_attempts_no_delete",
            [],
        )
        .unwrap();
    assert!(!v52_matches(&reopened, 52).unwrap());
    drop(reopened);
    let _ = std::fs::remove_file(path);
}

#[test]
fn v52_attempt_binding_is_immutable_and_readiness_checks_history() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 52).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    insert_grant(&connection, [1; 16], [2; 16], [4; 32]);
    insert_binding(&connection, [3; 16], [1; 16], "owner");
    insert_admission(&connection, [2; 16], "owner", [4; 32]);
    connection.execute(
        "INSERT INTO provider_secondary_profile_attempts
         (dispatch_attempt_id,grant_id,binding_id,provider_idempotency_key,profile_digest,pricing_revision_digest)
         VALUES (?1,?2,?3,'key',?4,?5)",
        rusqlite::params![[5_u8;16],[1_u8;16],[3_u8;16],[4_u8;32],[5_u8;32]],
    ).unwrap();
    assert!(v52_matches(&connection, 52).unwrap());
    assert!(connection.execute(
        "UPDATE provider_secondary_profile_attempts SET profile_digest=?2 WHERE dispatch_attempt_id=?1",
        rusqlite::params![[5_u8;16],[9_u8;32]],
    ).is_err(), "the historical profile association is immutable");

    connection
        .execute(
            "DROP TRIGGER provider_secondary_profile_attempts_immutable",
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE provider_secondary_profile_attempts SET provider_idempotency_key='wrong-key'
         WHERE dispatch_attempt_id=?1",
            [[5_u8; 16]],
        )
        .unwrap();
    assert!(
        !secondary_profile_attempts_match(&connection).unwrap(),
        "or mismatched admission key"
    );
    connection
        .execute(
            "UPDATE provider_secondary_profile_attempts SET provider_idempotency_key='key'
         WHERE dispatch_attempt_id=?1",
            [[5_u8; 16]],
        )
        .unwrap();
    assert!(secondary_profile_attempts_match(&connection).unwrap());
    connection
        .execute(
            "DROP TRIGGER provider_secondary_profile_bindings_immutable",
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE provider_secondary_profile_bindings SET owner_id='wrong-owner' WHERE binding_id=?1",
            [[3_u8; 16]],
        )
        .unwrap();
    assert!(
        !secondary_profile_attempts_match(&connection).unwrap(),
        "the grant owner must match historical admission"
    );
}

#[test]
fn managed_provider_store_rejects_orphan_profile_attempt_association() {
    let path = std::env::temp_dir().join(format!(
        "runne-v52-managed-profile-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let store = crate::provider::SqliteProviderExecutionStore::open(&path).unwrap();
    drop(store);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    connection.execute(
        "INSERT INTO provider_secondary_profile_attempts
         (dispatch_attempt_id,grant_id,binding_id,provider_idempotency_key,profile_digest,pricing_revision_digest)
         VALUES (?1,?2,?3,'missing-admission',?4,?5)",
        rusqlite::params![[6_u8;16],[7_u8;16],[8_u8;16],[9_u8;32],[10_u8;32]],
    ).unwrap();
    drop(connection);

    assert!(
        crate::provider::SqliteProviderExecutionStore::open(&path).is_err(),
        "managed-store readiness must reject an orphan association"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn managed_latest_schema_rejects_missing_inherited_cleanup_guard() {
    for (filename, ddl) in [
        (
            "legacy-credential-index",
            "DROP INDEX credential_cleanup_recovery_one_live",
        ),
        (
            "local-command-fence",
            "DROP TRIGGER schema_v12_fence_taskrun_local_command_attempts_update",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir(&daemon).unwrap();
        let path = daemon.join(format!("latest-{filename}.sqlite"));
        let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
        apply_migrations(&connection).unwrap();
        assert_eq!(schema_marker(&connection), CURRENT_SCHEMA_VERSION);
        assert!(v63_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap());
        drop(connection);

        // Prove a valid latest-schema database reopens before corruption.
        drop(open_managed_connection(&path, ConnectionMode::Writer).unwrap());
        let raw = Connection::open(&path).unwrap();
        raw.execute_batch(ddl).unwrap();
        drop(raw);
        assert!(
            open_managed_connection(&path, ConnectionMode::Writer).is_err(),
            "latest managed admission must reject inherited tampering: {filename}"
        );
    }
}

#[test]
fn readiness_rejects_orphan_binding_and_enabled_grant_without_current_binding() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 52).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    insert_grant(&connection, [21; 16], [22; 16], [23; 32]);
    insert_binding(&connection, [24; 16], [21; 16], "owner");
    assert!(v52_matches(&connection, 52).unwrap());

    connection.execute(
        "INSERT INTO provider_secondary_profile_bindings
         (binding_id,grant_id,owner_id,authority_revision,scope,activation_binding_kind,activation_binding_digest,created_at)
         VALUES (?1,?2,'orphan',1,'provider.dispatch','protected_v2',?3,1)",
        rusqlite::params![[25_u8;16],[26_u8;16],[27_u8;32]],
    ).unwrap();
    assert!(
        !v52_matches(&connection, 52).unwrap(),
        "unreferenced authorization bindings are corruption"
    );
}

fn insert_grant(
    connection: &Connection,
    grant: [u8; 16],
    authority: [u8; 16],
    profile_digest: [u8; 32],
) {
    connection
        .execute(
            "INSERT INTO provider_secondary_profile_grants
         (grant_id,runtime_authority_id,database_generation,provider_id,profile_id,credential_realm,
          profile_digest,pricing_revision_digest,token_budget_limit,token_budget_reserved,token_budget_settled,
          cost_budget_limit_micros,cost_budget_reserved_micros,cost_budget_settled_micros,enabled,created_at)
         VALUES (?1,?2,1,'openai-background','profile/1','openai-background',?3,?4,100,0,0,200,0,0,1,1)",
            rusqlite::params![
                grant,
                authority,
                profile_digest,
                [5_u8; 32]
            ],
        )
        .unwrap();
}

fn insert_binding(connection: &Connection, binding: [u8; 16], grant: [u8; 16], owner: &str) {
    connection.execute(
        "INSERT INTO provider_secondary_profile_bindings
         (binding_id,grant_id,owner_id,authority_revision,scope,activation_binding_kind,activation_binding_digest,created_at)
         VALUES (?1,?2,?3,1,'provider.dispatch','protected_v2',?4,1)",
        rusqlite::params![binding,grant,owner,[3_u8;32]],
    ).unwrap();
}

fn insert_admission(
    connection: &Connection,
    authority: [u8; 16],
    owner: &str,
    profile_digest: [u8; 32],
) {
    connection
        .execute(
            "INSERT INTO provider_execution_admissions (
          provider_idempotency_key,semantic_digest,principal_id,conversation_id,taskrun_id,
          execution_attempt_id,call_id,dispatch_attempt_id,authority_id,authority_revision,
          permit_id,token_reservation_id,cost_reservation_id,runtime_authority_id,
          database_generation,generation,fencing_token,prepared_digest,render_digest,
          profile_digest,pricing_revision_digest,requested_input_tokens,requested_output_tokens,
          max_cost_micros,currency,issued_at,expires_at,owner_id,scope,capability_grant_id,
          capability_revision,capability_expires_at,capability_revocation_epoch,
          capability_revocation_observed,approval_id,approval_revision,approval_expires_at,
          approval_revocation_epoch,approval_revocation_observed,activation_binding_kind,
          activation_binding_digest
         ) VALUES ('key',?1,'principal',?2,?3,?4,?5,?6,?7,1,?8,?9,?10,?7,1,1,1,
                   ?11,?12,?13,?14,1,1,10,'USD',1,2,?15,'provider.dispatch','cap',1,
                   2,0,0,'approval',1,2,0,0,'protected_v2',?16)",
            rusqlite::params![
                [10_u8; 32],
                [11_u8; 16],
                [12_u8; 16],
                [13_u8; 16],
                [14_u8; 16],
                [5_u8; 16],
                authority,
                [15_u8; 16],
                [16_u8; 16],
                [17_u8; 16],
                [18_u8; 32],
                [19_u8; 32],
                profile_digest,
                [5_u8; 32],
                owner,
                [3_u8; 32]
            ],
        )
        .unwrap();
}
