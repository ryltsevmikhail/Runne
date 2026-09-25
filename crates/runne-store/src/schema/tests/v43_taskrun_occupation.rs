#[test]
fn v43_backfills_claims_as_active_unknown_across_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("occupation-v43.sqlite");
    let connection = Connection::open(&path).unwrap();
    apply_migrations_internal(&connection, 42).unwrap();
    connection.execute(
        "INSERT INTO taskrun_assignments(taskrun_id,attempt_id,node_id,node_epoch,fence,capability_descriptor,lease_expires_at_ms,command_id,admitted_event_id,started_event_id) VALUES(?1,?2,?3,1,1,'linux-executor-v1',9999999999999,?4,?5,?6)",
        params![[1_u8;16].as_slice(),[2_u8;16].as_slice(),[3_u8;16].as_slice(),[4_u8;16].as_slice(),[5_u8;16].as_slice(),[6_u8;16].as_slice()],
    ).unwrap();
    apply_migrations(&connection).unwrap();
    drop(connection);
    let reopened = Connection::open(path).unwrap();
    assert!(v43_matches(&reopened, 43).unwrap());
    let state: (String, String) = reopened.query_row(
        "SELECT state,dispatch_intent FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=1",
        [[1_u8;16].as_slice()], |row| Ok((row.get(0)?,row.get(1)?)),
    ).unwrap();
    assert_eq!(state, ("active".into(), "unknown".into()));
    assert!(v43_matches(&reopened, 43).unwrap());
}

#[test]
fn v43_admission_rejects_drift_inherited_from_v42() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    assert!(v43_matches(&connection, 43).unwrap());
    connection
        .execute_batch("DROP TRIGGER taskrun_assignments_immutable;")
        .unwrap();
    assert!(!v43_matches(&connection, 43).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}

#[test]
fn v43_admission_requires_global_renewal_command_id_guards() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    assert!(v43_matches(&connection, 43).unwrap());
    connection
        .execute_batch("DROP TRIGGER global_command_id_from_taskrun_claim_receipts_v43;")
        .unwrap();
    assert!(!v43_matches(&connection, 43).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}

#[test]
fn v43_renewal_receipts_are_append_only_and_admission_checks_the_guards() {
    let connection = v43_database_with_claim();
    let renewal_id = [31_u8; 16];
    insert_test_renewal(&connection, &renewal_id).unwrap();
    assert!(connection
        .execute(
            "UPDATE taskrun_assignment_lease_renewals SET renewal_id=?1 WHERE renewal_id=?2",
            params![[32_u8; 16].as_slice(), renewal_id.as_slice()],
        )
        .is_err());
    assert!(connection
        .execute(
            "DELETE FROM taskrun_assignment_lease_renewals WHERE renewal_id=?1",
            [renewal_id.as_slice()],
        )
        .is_err());

    connection
        .execute_batch(
            "DROP TRIGGER taskrun_assignment_lease_renewals_immutable;",
        )
        .unwrap();
    assert!(!v43_matches(&connection, 43).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}

#[test]
fn v43_admission_rejects_cross_table_renewal_id_collision_after_guard_removal() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection.execute(
        "INSERT INTO taskrun_assignments(taskrun_id,attempt_id,node_id,node_epoch,fence,capability_descriptor,lease_expires_at_ms,command_id,admitted_event_id,started_event_id) VALUES(?1,?2,?3,1,1,'linux-executor-v1',9999999999999,?4,?5,?6)",
        params![[11_u8;16].as_slice(),[12_u8;16].as_slice(),[13_u8;16].as_slice(),[14_u8;16].as_slice(),[15_u8;16].as_slice(),[16_u8;16].as_slice()],
    ).unwrap();
    connection.execute(
        "INSERT INTO taskrun_assignment_occupations(taskrun_id,fence,attempt_id,node_id,node_epoch,lease_expires_at_ms,state,dispatch_intent) VALUES(?1,1,?2,?3,1,9999999999999,'active','unknown')",
        params![[11_u8;16].as_slice(),[12_u8;16].as_slice(),[13_u8;16].as_slice()],
    ).unwrap();
    insert_test_renewal(&connection, &[31_u8; 16]).unwrap();
    insert_command_receipt(&connection, "command_receipts", &[32_u8; 16]).unwrap();
    connection.execute_batch(
        "DROP TRIGGER taskrun_assignment_lease_renewals_immutable;",
    ).unwrap();
    connection.execute(
        "UPDATE taskrun_assignment_lease_renewals SET renewal_id=?1 WHERE renewal_id=?2",
        params![[32_u8; 16].as_slice(), [31_u8; 16].as_slice()],
    ).unwrap();
    // This models a stored row altered after its append-only guard was removed;
    // classification must reject the collision even though the row relationships remain valid.
    assert!(!v43_matches(&connection, 43).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}

#[test]
fn v43_renewal_ids_collide_with_all_command_receipts_in_both_directions() {
    for table in [
        "command_receipts",
        "project_workspace_command_receipts",
        "taskrun_claim_receipts",
    ] {
        let connection = v43_database_with_claim();
        let id = [31_u8; 16];
        insert_command_receipt(&connection, table, &id).unwrap();
        assert!(
            insert_test_renewal(&connection, &id).is_err(),
            "renewal accepted {table} ID"
        );

        let connection = v43_database_with_claim();
        insert_test_renewal(&connection, &id).unwrap();
        assert!(
            insert_command_receipt(&connection, table, &id).is_err(),
            "{table} accepted renewal ID"
        );
    }
}

fn v43_database_with_claim() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection.execute(
        "INSERT INTO taskrun_assignments(taskrun_id,attempt_id,node_id,node_epoch,fence,capability_descriptor,lease_expires_at_ms,command_id,admitted_event_id,started_event_id) VALUES(?1,?2,?3,1,1,'linux-executor-v1',9999999999999,?4,?5,?6)",
        params![[11_u8;16].as_slice(),[12_u8;16].as_slice(),[13_u8;16].as_slice(),[14_u8;16].as_slice(),[15_u8;16].as_slice(),[16_u8;16].as_slice()],
    ).unwrap();
    connection.execute(
        "INSERT INTO taskrun_assignment_occupations(taskrun_id,fence,attempt_id,node_id,node_epoch,lease_expires_at_ms,state,dispatch_intent) VALUES(?1,1,?2,?3,1,9999999999999,'active','unknown')",
        params![[11_u8;16].as_slice(),[12_u8;16].as_slice(),[13_u8;16].as_slice()],
    ).unwrap();
    assert!(v43_matches(&connection, 43).unwrap());
    connection
}

fn insert_test_renewal(connection: &Connection, id: &[u8; 16]) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO taskrun_assignment_lease_renewals(renewal_id,taskrun_id,fence,attempt_id,node_id,node_epoch,lease_duration_ms,lease_expires_at_ms) VALUES(?1,?2,1,?3,?4,1,100,9999999999999)",
        params![id.as_slice(), [11_u8;16].as_slice(), [12_u8;16].as_slice(), [13_u8;16].as_slice()],
    )
}

fn insert_command_receipt(
    connection: &Connection,
    table: &str,
    id: &[u8; 16],
) -> rusqlite::Result<usize> {
    match table {
        "command_receipts" => connection.execute(
            "INSERT INTO command_receipts(command_id,idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome,committed_at) VALUES(?1,x'01',x'02',zeroblob(32),x'03',1)", [id.as_slice()],
        ),
        "project_workspace_command_receipts" => connection.execute(
            "INSERT INTO project_workspace_command_receipts(command_id,runtime_authority_id,principal_id,operation,aggregate_kind,aggregate_id,idempotency_key,semantic_fingerprint,outcome,committed_at) VALUES(?1,'authority','principal',1,1,zeroblob(16),'key',zeroblob(32),x'01',1)", [id.as_slice()],
        ),
        "taskrun_claim_receipts" => connection.execute(
            "INSERT INTO taskrun_claim_receipts(command_id,idempotency_scope_bytes,idempotency_key,fingerprint,taskrun_id,attempt_id,node_id,node_epoch,fence,lease_expires_at_ms,new_version,admitted_event_id,started_event_id) VALUES(?1,x'01',x'02',zeroblob(32),?2,?3,?4,1,1,9999999999999,4,?5,?6)",
            params![id.as_slice(), [11_u8;16].as_slice(), [12_u8;16].as_slice(), [13_u8;16].as_slice(), [15_u8;16].as_slice(), [16_u8;16].as_slice()],
        ),
        _ => unreachable!(),
    }
}

#[test]
fn v43_admission_rejects_occupation_node_mismatch() {
    let connection = v43_database_with_claim();
    connection
        .execute(
            "UPDATE taskrun_assignment_occupations SET node_id=?1 WHERE taskrun_id=?2 AND fence=1",
            params![[17_u8; 16].as_slice(), [11_u8; 16].as_slice()],
        )
        .unwrap();
    assert!(!v43_matches(&connection, 43).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}

#[test]
fn v43_admission_rejects_unproven_release_state() {
    let connection = v43_database_with_claim();
    connection.execute(
        "UPDATE taskrun_assignment_occupations SET state='released' WHERE taskrun_id=?1 AND fence=1",
        [[11_u8;16].as_slice()],
    ).unwrap();
    assert!(!v43_matches(&connection, 43).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}

#[test]
fn v43_admission_rejects_orphan_occupation() {
    let connection = v43_database_with_claim();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    connection.execute(
        "INSERT INTO taskrun_assignment_occupations(taskrun_id,fence,attempt_id,node_id,node_epoch,lease_expires_at_ms,state,dispatch_intent) VALUES(?1,2,?2,?3,1,9999999999999,'active','unknown')",
        params![[21_u8;16].as_slice(),[22_u8;16].as_slice(),[23_u8;16].as_slice()],
    ).unwrap();
    assert!(!v43_matches(&connection, 43).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}
