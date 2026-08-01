#[test]
fn preflight_rejects_partial_v9_that_contains_legacy_required_fragments() {
    let path = candidate_database("partial-v9");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE schema_lineage (schema_version INTEGER PRIMARY KEY, provenance TEXT NOT NULL);
             INSERT INTO schema_lineage VALUES (9, 'released-v8-to-strict-v9');
             CREATE TABLE verification_evidence (
                 evidence_id BLOB PRIMARY KEY CHECK(length(evidence_id) = 16),
                 layer INTEGER NOT NULL CHECK(layer IN (0, 1, 2, 3, 4, 5)),
                 verified_by TEXT NOT NULL CHECK(length(verified_by) > 0)
             );
             CREATE TABLE consumption_intents (
                 intent_id BLOB PRIMARY KEY CHECK(length(intent_id) = 16),
                 idempotency_key TEXT NOT NULL UNIQUE,
                 integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32)
             );",
        )
        .unwrap();
    drop(connection);
    let before = snapshot(&path);

    assert!(preflight_existing_file(&path).is_err());
    assert_unchanged(&path, &before);
}

#[test]
fn preflight_rejects_existing_empty_lineage_and_fake_v8_before_wal() {
    for (name, schema) in [
        (
            "no-schema-version",
            "CREATE TABLE unrelated (value TEXT NOT NULL);",
        ),
        (
            "fake-v8",
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY);\
             INSERT INTO schema_version VALUES (8);",
        ),
        (
            "partial-v7",
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY);\
             INSERT INTO schema_version VALUES (7);",
        ),
    ] {
        let path = candidate_database(name);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("DROP TABLE schema_version;")
            .unwrap();
        connection.execute_batch(schema).unwrap();
        drop(connection);
        let before = snapshot(&path);

        assert!(preflight_existing_file(&path).is_err(), "{name}");
        assert_unchanged(&path, &before);
    }
}

#[test]
fn shared_opener_rejects_hot_wal_candidate_without_changing_any_file() {
    let path = candidate_database("hot-wal");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
    let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    reader
        .execute_batch("BEGIN; SELECT * FROM candidate_data;")
        .unwrap();
    writer
        .execute("INSERT INTO candidate_data VALUES ('hot-wal')", [])
        .unwrap();
    drop(writer);
    let before = snapshot_file_set(&path);
    assert!(
        before
            .iter()
            .any(|(file, _)| file.to_string_lossy().ends_with("-wal"))
    );

    assert!(open_with_pragmas(path.to_str().unwrap()).is_err());
    assert_file_set_unchanged(&before);
    drop(reader);
}

#[test]
fn preflight_rejects_index_semantic_changes_and_unnamed_critical_objects() {
    for (name, definition) in [
        (
            "unique-index",
            "CREATE UNIQUE INDEX idx_evidence_run ON verification_evidence(run_id);",
        ),
        (
            "descending-index",
            "CREATE INDEX idx_evidence_run ON verification_evidence(run_id DESC);",
        ),
        (
            "nocase-index",
            "CREATE INDEX idx_evidence_run ON verification_evidence(run_id COLLATE NOCASE);",
        ),
    ] {
        let index_path = canonical_v9_database(name);
        let connection = Connection::open(&index_path).unwrap();
        connection
            .execute_batch(&format!("DROP INDEX idx_evidence_run; {definition}"))
            .unwrap();
        drop(connection);
        let before = snapshot_file_set(&index_path);
        assert!(preflight_existing_file(&index_path).is_err());
        assert_file_set_unchanged(&before);
    }

    let trigger_path = canonical_v9_database("anonymous-trigger");
    let connection = Connection::open(&trigger_path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER audit AFTER INSERT ON verification_evidence
             BEGIN SELECT 1; END;",
        )
        .unwrap();
    drop(connection);
    let before = snapshot_file_set(&trigger_path);
    assert!(preflight_existing_file(&trigger_path).is_err());
    assert_file_set_unchanged(&before);
}

#[test]
fn preflight_rejects_explicit_candidate_remnant_catalog_entries() {
    for remnant in [
        "verification_evidence_v10",
        "consumption_intents_v11",
        "candidate_backup",
    ] {
        let path = canonical_v9_database(remnant);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(&format!("CREATE TABLE {remnant} (value TEXT NOT NULL);"))
            .unwrap();
        drop(connection);
        let before = snapshot_file_set(&path);

        assert!(preflight_existing_file(&path).is_err(), "{remnant}");
        assert_file_set_unchanged(&before);
    }
}

#[test]
fn preflight_rejects_v11_authority_table_with_same_columns_and_missing_constraints() {
    let path = current_database("v11-authority-constraints");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE candidate_data (value TEXT NOT NULL);
             INSERT INTO candidate_data VALUES ('unchanged');",
        )
        .unwrap();
    apply_migrations(&connection).unwrap();
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
    let new_conn = open_with_pragmas(new_path.to_str().unwrap()).unwrap();
    apply_migrations(&new_conn).unwrap();
    drop(new_conn);

    let v8_path = std::env::temp_dir().join("gocode-schema-preflight-v8.sqlite");
    let _ = std::fs::remove_file(&v8_path);
    let v8_conn = Connection::open(&v8_path).unwrap();
    apply_migrations(&v8_conn).unwrap();
    v8_conn
        .execute_batch(
            "DROP TABLE provider_effect_authorities;
             DROP TABLE provider_dispatch_attempts;
             DROP TABLE provider_prepared_requests;
             DROP TABLE schema_lineage;
             DROP TABLE consumption_intents;
             DROP TABLE verification_evidence;
             DELETE FROM schema_version WHERE version >= 9;",
        )
        .unwrap();
    drop(v8_conn);
    assert!(open_with_pragmas(v8_path.to_str().unwrap()).is_ok());

    assert!(open_with_pragmas(new_path.to_str().unwrap()).is_ok());

    for path in [new_path, v8_path] {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
