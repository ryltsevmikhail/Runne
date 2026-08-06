#[test]
fn verification_stores_reject_candidate_schema_without_side_effects() {
    let path = candidate_database("verification-stores");
    let before = snapshot(&path);

    assert!(SqliteEvidenceStore::open(&path).is_err());
    assert_unchanged(&path, &before);
    assert!(SqliteIntentStore::open(&path).is_err());
    assert_unchanged(&path, &before);
}

#[test]
fn all_store_entry_points_reject_future_schema_versions_without_side_effects() {
    for version in [10, 11] {
        let path = candidate_database_version(&format!("all-entry-points-v{version}"), version);
        let before = snapshot(&path);

        assert!(
            StoreTransaction::open(
                path.to_str().unwrap(),
                RuntimeAuthorityId("test-host".into()),
                available_guard(),
            )
            .is_err()
        );
        assert_unchanged(&path, &before);
        assert!(SqliteMigrationControlStore::open(&path).is_err());
        assert_unchanged(&path, &before);
        assert!(SqliteAtomicPreEffectStore::open(&path).is_err());
        assert_unchanged(&path, &before);
        assert!(SqliteEvidenceStore::open(&path).is_err());
        assert_unchanged(&path, &before);
        assert!(SqliteIntentStore::open(&path).is_err());
        assert_unchanged(&path, &before);
    }
}

#[test]
fn preflight_rejects_partial_v9_that_contains_legacy_required_fragments() {
    let path = released_v8_database("partial-v9");
    assert_clean_preflight(&path);
    apply_partial_v9_lineage_marker(&path);
    assert_no_sidecars(&path);
    let before = capture_rejection_no_mutation_oracle(&path);

    assert_rejected_without_sidecars(&path, &before);
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
