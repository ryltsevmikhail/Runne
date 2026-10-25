#[test]
fn v39_lineage_rebuild_preserves_rows_and_admits_the_submit_origin() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 36).unwrap();
    connection
        .execute(
            "INSERT INTO task_run_workspace_lineage
             (taskrun_id, workspace_id, project_id, classification,
              origin_command_id, origin_operation)
             VALUES (?1, ?2, ?3, 'canonical', ?4, 1)",
            params![
                [1_u8; 16].as_slice(),
                [2_u8; 16].as_slice(),
                [3_u8; 16].as_slice(),
                [4_u8; 16].as_slice()
            ],
        )
        .unwrap();

    apply_migrations(&connection).unwrap();

    assert_eq!(schema_marker(&connection), CURRENT_SCHEMA_VERSION);
    assert!(
        v69_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap(),
        "upgraded structure: marker={:?} inherited={:?} receipts={:?} triggers={:?} lineage={:?}",
        connection
            .query_row(
                "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
                [],
                |row| Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?
                )),
            )
            .unwrap(),
        v37_structure_matches(&connection).unwrap(),
        project_workspace_schema::v36_receipt_table_matches(&connection).unwrap(),
        project_workspace_schema::validation::global_command_triggers_match(&connection).unwrap(),
        v39_lineage_table_matches(&connection).unwrap(),
    );
    let preserved: i64 = connection
        .query_row(
            "SELECT origin_operation FROM task_run_workspace_lineage
             WHERE taskrun_id = ?1",
            params![[1_u8; 16].as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(preserved, 1, "pre-existing create lineage survives");

    assert!(
        connection
            .execute(
                "INSERT INTO task_run_workspace_lineage
                 (taskrun_id, workspace_id, project_id, classification,
                  origin_command_id, origin_operation)
                 VALUES (?1, ?2, ?3, 'canonical', ?4, 20)",
                params![
                    [5_u8; 16].as_slice(),
                    [2_u8; 16].as_slice(),
                    [3_u8; 16].as_slice(),
                    [6_u8; 16].as_slice()
                ],
            )
            .is_ok(),
        "submit origin 20 is admitted after the rebuild"
    );
    assert!(
        connection
            .execute(
                "INSERT INTO task_run_workspace_lineage
                 (taskrun_id, workspace_id, project_id, classification,
                  origin_command_id, origin_operation)
                 VALUES (?1, ?2, ?3, 'canonical', ?4, 21)",
                params![
                    [7_u8; 16].as_slice(),
                    [2_u8; 16].as_slice(),
                    [3_u8; 16].as_slice(),
                    [8_u8; 16].as_slice()
                ],
            )
            .is_err(),
        "unknown origin operations stay rejected"
    );
}

#[test]
fn lineage_ddl_drift_is_rejected_per_schema_version() {
    // A v36 database whose lineage table was rebuilt with the v39 DDL
    // without advancing the schema version must stay rejected.
    let drifted = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&drifted, 36).unwrap();
    assert!(project_workspace_schema::v36_matches(&drifted, 36).unwrap());
    drifted.execute_batch(MIGRATION_V39_LINEAGE).unwrap();
    drifted
        .execute_batch(
            "INSERT INTO task_run_workspace_lineage_v39
             SELECT * FROM task_run_workspace_lineage;
             DROP TABLE task_run_workspace_lineage;
             ALTER TABLE task_run_workspace_lineage_v39
             RENAME TO task_run_workspace_lineage;",
        )
        .unwrap();
    assert!(
        !project_workspace_schema::v36_matches(&drifted, 36).unwrap(),
        "v39 lineage DDL under a v36 marker is DDL drift"
    );
    assert!(classify_schema_version(&drifted).is_err());

    // A v39 database whose lineage table was rolled back to the v18 DDL
    // must equally stay rejected.
    let rolled_back = Connection::open_in_memory().unwrap();
    apply_migrations(&rolled_back).unwrap();
    assert!(v69_matches(&rolled_back, CURRENT_SCHEMA_VERSION).unwrap());
    let v18_lineage = project_workspace_schema::MIGRATION_V18
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with("CREATE TABLE task_run_workspace_lineage "))
        .unwrap();
    rolled_back
        .execute_batch(&format!(
            "{};",
            v18_lineage.replace(
                "CREATE TABLE task_run_workspace_lineage",
                "CREATE TABLE task_run_workspace_lineage_drift"
            )
        ))
        .unwrap();
    rolled_back
        .execute_batch(
            "INSERT INTO task_run_workspace_lineage_drift
             SELECT * FROM task_run_workspace_lineage;
             DROP TRIGGER text_only_taskrun_lineage_no_workspace_collision;
             DROP TABLE task_run_workspace_lineage;
             ALTER TABLE task_run_workspace_lineage_drift
             RENAME TO task_run_workspace_lineage;",
        )
        .unwrap();
    rolled_back.execute_batch("CREATE TRIGGER text_only_taskrun_lineage_no_workspace_collision BEFORE INSERT ON text_only_taskrun_lineage WHEN EXISTS(SELECT 1 FROM task_run_workspace_lineage WHERE taskrun_id=NEW.taskrun_id) BEGIN SELECT RAISE(ABORT,'TaskRun lineage owner collision'); END;").unwrap();
    assert!(
        !v69_matches(&rolled_back, CURRENT_SCHEMA_VERSION).unwrap(),
        "v18 lineage DDL under a v40 marker is DDL drift"
    );
    assert!(classify_schema_version(&rolled_back).is_err());
}

#[test]
fn v39_reopens_full_and_no_v19_lineages() {
    for no_v19_lineage in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = {
            let daemon = directory.path().join("runne-daemon");
            std::fs::create_dir_all(&daemon).unwrap();
            daemon.join("taskrun-lineage-v39.sqlite")
        };
        let connection = Connection::open(&path).unwrap();
        if no_v19_lineage {
            apply_migrations_internal(&connection, 35).unwrap();
        } else {
            apply_migrations_internal(&connection, 19).unwrap();
        }
        apply_migrations(&connection).unwrap();
        assert!(
            v69_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap(),
            "lineage {no_v19_lineage}"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COALESCE(SUM(version), 0) FROM schema_version",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            if no_v19_lineage { 2396 } else { 2415 }
        );
        drop(connection);
        drop(open_managed_connection(&path, ConnectionMode::Writer).unwrap());
    }
}
