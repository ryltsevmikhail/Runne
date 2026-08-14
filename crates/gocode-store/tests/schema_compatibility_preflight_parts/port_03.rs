#[test]
fn preflight_rejects_v11_authority_table_with_same_columns_and_missing_constraints() {
    let path = current_database("v11-authority-constraints");
    let connection = Connection::open(&path).unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE candidate_data (value TEXT NOT NULL);
             INSERT INTO candidate_data VALUES ('unchanged');",
        )
        .unwrap();
    connection
        .execute_batch(
            "DROP TABLE provider_effect_authorities;
             CREATE TABLE provider_effect_authorities (
                 authority_id BLOB NOT NULL,
                 revision INTEGER NOT NULL,
                 attempt_id BLOB NOT NULL,
                 permit_id BLOB NOT NULL,
                 capability_grant_id TEXT NOT NULL,
                 token_reservation_id BLOB NOT NULL,
                 cost_reservation_id BLOB NOT NULL,
                 prepared_digest BLOB NOT NULL,
                 render_digest BLOB NOT NULL,
                 profile_digest BLOB NOT NULL,
                 owner_id TEXT NOT NULL,
                 scope TEXT NOT NULL,
                 fencing_token INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL,
                 revoked INTEGER NOT NULL,
                 consumed INTEGER NOT NULL,
                 consumed_intent_id TEXT,
                 PRIMARY KEY(authority_id, revision)
                 /* authority_idblobnotnullcheck(length(authority_id)=16andauthority_id!=zeroblob(16)) revisioninteger not null check(revision>0) attempt_idblobnotnullcheck(length(attempt_id)=16) permit_idblobnotnullcheck(length(permit_id)=16) capability_grant_idtextnotnullcheck(length(capability_grant_id)between1and256) token_reservation_idblobnotnullcheck(length(token_reservation_id)=16) cost_reservation_idblobnotnullcheck(length(cost_reservation_id)=16) prepared_digestblobnotnullcheck(length(prepared_digest)=32) render_digestblobnotnullcheck(length(render_digest)=32) profile_digestblobnotnullcheck(length(profile_digest)=32) owner_idtextnotnullcheck(length(owner_id)between1and256) scopetextnotnullcheck(length(scope)between1and256) fencing_tokeninteger not null check(fencing_token>0) revokedinteger not null check(revoked in (0,1)) consumedinteger not null check(consumed in (0,1)) consumed_intent_idtextunique primarykey(authority_id,revision) check((consumed=0andconsumed_intent_idisnull)or(consumed=1andconsumed_intent_idisnotnull)) */
             );",
        )
        .unwrap();
    drop(connection);
    let before = snapshot(&path);

    assert!(preflight_existing_file(&path).is_err());
    assert_unchanged(&path, &before);
}

#[test]
fn shared_opener_admits_new_released_v8_and_canonical_v9_files() {
    let new_path = std::env::temp_dir().join("gocode-schema-preflight-new.sqlite");
    let _ = std::fs::remove_file(&new_path);
    let new_conn = open_managed_connection(&new_path, ConnectionMode::Writer).unwrap();
    apply_migrations(&new_conn).unwrap();
    drop(new_conn);

    let v8_path = std::env::temp_dir().join("gocode-schema-preflight-v8.sqlite");
    let _ = std::fs::remove_file(&v8_path);
    let v8_conn = open_managed_connection(&v8_path, ConnectionMode::Writer).unwrap();
    apply_migrations(&v8_conn).unwrap();
    let triggers = v8_conn
        .prepare("SELECT name FROM sqlite_master WHERE type='trigger'")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for trigger in triggers {
        v8_conn
            .execute_batch(&format!("DROP TRIGGER \"{trigger}\";"))
            .unwrap();
    }
    v8_conn
        .execute_batch(
            "DROP TABLE aggregate_state_snapshots;
             DROP TABLE task_run_workspace_lineage;
             DROP TABLE workspace_identity_history;
             DROP TABLE project_workspace_command_receipts;
             DROP TABLE root_admission_nonces;
             DROP TABLE workspaces;
             DROP TABLE projects;
             DROP TABLE bootstrap_reservation_tombstones;
             DROP TABLE bootstrap_reservations;
             DROP TABLE bootstrap_last_observed_clock;
             DROP TABLE provider_credential_effect_bindings;
             DROP TABLE provider_credential_provisions;
             DROP TABLE provider_credential_clock_high_water;
             DROP TABLE provider_credential_versions;
             DROP TABLE provider_effect_authorities;
             DROP TABLE provider_dispatch_attempts;
             DROP TABLE provider_prepared_requests;
             DROP TABLE schema_lineage;
             DROP TABLE consumption_intents;
             DROP TABLE verification_evidence;
             DELETE FROM schema_version WHERE version >= 9;",
        )
        .unwrap();
    drop(v8_conn);
    assert!(open_managed_connection(&v8_path, ConnectionMode::Writer).is_ok());

    assert!(open_managed_connection(&new_path, ConnectionMode::Writer).is_ok());

    for path in [new_path, v8_path] {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
