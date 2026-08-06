use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
struct RejectionNoMutationOracle {
    main_db_sha256: [u8; 32],
    sqlite_master: Vec<(String, String, String, Option<String>)>,
    schema_versions: Vec<(i64, Option<String>)>,
    schema_lineage: Option<Vec<(i64, String)>>,
    user_version: i64,
    sidecars: Vec<(String, bool)>,
}

fn capture_rejection_no_mutation_oracle(path: &Path) -> RejectionNoMutationOracle {
    let main_db_sha256 = Sha256::digest(std::fs::read(path).unwrap()).into();
    let connection = immutable_read_only_connection(path);
    let sqlite_master = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name, tbl_name, sql")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let version_has_applied_at: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('schema_version') WHERE name = 'applied_at')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let schema_versions = connection
        .prepare(if version_has_applied_at {
            "SELECT version, applied_at FROM schema_version ORDER BY version"
        } else {
            "SELECT version, NULL FROM schema_version ORDER BY version"
        })
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let lineage_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_lineage')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let schema_lineage = lineage_exists.then(|| {
        connection
            .prepare("SELECT schema_version, provenance FROM schema_lineage ORDER BY schema_version")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    });
    let user_version = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    drop(connection);
    let sidecars = ["-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| (suffix.to_owned(), PathBuf::from(format!("{}{suffix}", path.display())).exists()))
        .collect();

    RejectionNoMutationOracle {
        main_db_sha256,
        sqlite_master,
        schema_versions,
        schema_lineage,
        user_version,
        sidecars,
    }
}

fn assert_rejection_no_mutation_oracle(path: &Path, before: &RejectionNoMutationOracle) {
    let after = capture_rejection_no_mutation_oracle(path);
    assert_eq!(after, *before);
    for (suffix, existed_before) in &before.sidecars {
        assert!(
            *existed_before || !PathBuf::from(format!("{}{suffix}", path.display())).exists(),
            "rejection created {suffix}"
        );
    }
}

fn assert_rejected_without_sidecars(path: &Path, before: &RejectionNoMutationOracle) {
    assert_no_sidecars(path);
    assert!(preflight_existing_file(path).is_err());
    assert_no_sidecars(path);
    assert_rejection_no_mutation_oracle(path, before);
}

#[test]
fn status_9_covered_newer_schema_rejects_before_writable_open_with_exact_no_mutation_oracle() {
    let path = canonical_current_database("status-9-newer-schema");
    assert_clean_preflight(&path);
    apply_future_schema_marker(&path);
    assert_no_sidecars(&path);
    assert_future_schema_marker(&path);
    let before = capture_rejection_no_mutation_oracle(&path);

    assert_rejected_without_sidecars(&path, &before);
}

#[test]
fn status_10_partial_local_current_downgrade_preflight_rejects_without_mutation() {
    let path = canonical_current_database("status-10-local-current-downgrade");
    assert_clean_preflight(&path);
    apply_future_schema_marker(&path);
    assert_no_sidecars(&path);
    assert_future_schema_marker(&path);
    let before = capture_rejection_no_mutation_oracle(&path);

    assert_rejected_without_sidecars(&path, &before);
}

#[test]
fn status_12_covered_malformed_released_intermediate_boundary_rejects_without_mutation() {
    let path = released_v8_database("status-12-malformed-intermediate");
    assert_clean_preflight(&path);
    apply_partial_v9_lineage_marker(&path);
    assert_no_sidecars(&path);
    let before = capture_rejection_no_mutation_oracle(&path);

    assert_rejected_without_sidecars(&path, &before);
}

#[test]
fn status_13_covered_lineage_profile_contract_mismatch_fails_closed_without_mutation() {
    let path = canonical_current_database("status-13-lineage-profile-mismatch");
    assert_clean_preflight(&path);
    delete_schema_lineage(&path);
    assert_no_sidecars(&path);
    let before = capture_rejection_no_mutation_oracle(&path);

    assert_rejected_without_sidecars(&path, &before);
}
