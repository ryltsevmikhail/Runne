#[test]
fn v36_reopens_full_and_no_v19_v35_lineages() {
    for no_v19_lineage in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = { let daemon = directory.path().join("runne-daemon"); std::fs::create_dir_all(&daemon).unwrap(); daemon.join("project-workspace-v36.sqlite") };
        let connection = Connection::open(&path).unwrap();
        if no_v19_lineage {
            apply_migrations_internal(&connection, 35).unwrap();
            assert!(v35_matches(&connection, 35).unwrap());
        } else {
            apply_migrations_internal(&connection, 19).unwrap();
        }
        apply_migrations_internal(&connection, 36).unwrap();
        assert!(project_workspace_schema::v36_matches(&connection, 36).unwrap());
        assert_eq!(
            connection
                .query_row(
                    "SELECT COALESCE(SUM(version), 0) FROM schema_version",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            if no_v19_lineage { 647 } else { 666 }
        );
        drop(connection);
        drop(open_managed_connection(&path, ConnectionMode::Writer).unwrap());
    }
}

#[test]
fn v36_rejects_tampered_inherited_receipt_and_global_trigger_structure() {
    for mutation in [
        "ALTER TABLE provider_qualification_admission_fences ADD COLUMN tampered INTEGER",
        "DROP TRIGGER provider_qualification_fence_no_update",
        "DROP TRIGGER global_command_id_from_project_workspace_receipts",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 36).unwrap();
        connection.execute_batch(mutation).unwrap();
        assert!(
            !project_workspace_schema::v36_matches(&connection, 36).unwrap(),
            "{mutation}"
        );
        assert!(
            apply_migrations_internal(&connection, 36).is_err(),
            "{mutation}"
        );
    }

    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 36).unwrap();
    let receipt: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'project_workspace_command_receipts'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch(&format!(
            "DROP TABLE project_workspace_command_receipts; {}",
            receipt.replace("BETWEEN 1 AND 8", "BETWEEN 1 AND 9")
        ))
        .unwrap();
    assert!(!project_workspace_schema::v36_matches(&connection, 36).unwrap());
    assert!(apply_migrations_internal(&connection, 36).is_err());
}

#[test]
fn v18_marker_does_not_admit_the_v36_receipt_schema() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_through_v18_for_test(&connection).unwrap();
    replace_receipt_with_v36_schema(&connection);
    assert!(!project_workspace_schema::v18_matches(&connection, 18).unwrap());
    assert!(apply_migrations_internal(&connection, 36).is_err());
}

#[test]
fn v35_marker_does_not_admit_the_v36_receipt_schema() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 35).unwrap();
    assert!(v35_matches(&connection, 35).unwrap());
    replace_receipt_with_v36_schema(&connection);
    assert!(!v35_matches(&connection, 35).unwrap());
    assert!(apply_migrations_internal(&connection, 36).is_err());
}

#[test]
fn v36_preserves_a_v35_project_receipt_byte_for_byte() {
    use crate::codec::{ProjectWorkspaceReceipt, ProjectWorkspaceReceiptCodec, StoreCodec};
    use runne_domain::id::ProjectId;
    use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName};

    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 35).unwrap();
    let project_id = ProjectId::from_bytes([0x41; 16]);
    let outcome = ProjectWorkspaceReceiptCodec
        .encode(&ProjectWorkspaceReceipt::Project(Project::create(
            project_id,
            ProjectWorkspaceDisplayName::new("Preserved".into()).unwrap(),
        )))
        .unwrap();
    let command_id = [0x42_u8; 16];
    let fingerprint = [0x43_u8; 32];
    connection
        .execute(
            "INSERT INTO project_workspace_command_receipts
             (command_id,runtime_authority_id,principal_id,operation,aggregate_kind,aggregate_id,
              idempotency_key,semantic_fingerprint,outcome,committed_at)
             VALUES (?1,'v36-test','owner',1,1,?2,'create',?3,?4,7)",
            rusqlite::params![command_id, project_id.as_bytes(), fingerprint, outcome],
        )
        .unwrap();
    let before = receipt_row(&connection, command_id);
    project_workspace_schema::apply_v36_migration(&connection).unwrap();
    let after = receipt_row(&connection, command_id);
    assert_eq!(after, before);
    assert!(matches!(
        ProjectWorkspaceReceiptCodec.decode(&after.8),
        Ok(ProjectWorkspaceReceipt::Project(project)) if project.id() == project_id && project.display_name() == "Preserved"
    ));
}

fn replace_receipt_with_v36_schema(connection: &Connection) {
    connection
        .execute_batch(project_workspace_schema::MIGRATION_V36)
        .unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER global_command_id_from_command_receipts;
             DROP TRIGGER global_command_id_from_project_workspace_receipts;
             DROP TABLE project_workspace_command_receipts;
             ALTER TABLE project_workspace_command_receipts_v36
             RENAME TO project_workspace_command_receipts;",
        )
        .unwrap();
    for operation in ["insert", "update", "delete"] {
        connection
            .execute_batch(&v12_fence_trigger("project_workspace_command_receipts", operation).1)
            .unwrap();
    }
    connection
        .execute_batch(project_workspace_schema::GLOBAL_COMMAND_RECEIPT_TRIGGER)
        .unwrap();
    connection
        .execute_batch(project_workspace_schema::GLOBAL_PROJECT_WORKSPACE_RECEIPT_TRIGGER)
        .unwrap();
}

#[allow(clippy::type_complexity)]
fn receipt_row(
    connection: &Connection,
    command_id: [u8; 16],
) -> (
    Vec<u8>,
    String,
    String,
    i64,
    i64,
    Vec<u8>,
    String,
    Vec<u8>,
    Vec<u8>,
    i64,
) {
    connection
        .query_row(
            "SELECT command_id,runtime_authority_id,principal_id,operation,aggregate_kind,
                    aggregate_id,idempotency_key,semantic_fingerprint,outcome,committed_at
             FROM project_workspace_command_receipts WHERE command_id = ?1",
            [command_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .unwrap()
}
