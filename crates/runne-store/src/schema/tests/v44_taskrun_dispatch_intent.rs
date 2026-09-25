#[test]
fn v44_migration_backfills_blocking_claim_evidence_and_reopens() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("dispatch-v44.sqlite");
    let connection = Connection::open(&path).unwrap();
    apply_migrations_internal(&connection, 43).unwrap();
    connection.execute(
        "INSERT INTO taskrun_assignments(taskrun_id,attempt_id,node_id,node_epoch,fence,capability_descriptor,lease_expires_at_ms,command_id,admitted_event_id,started_event_id) VALUES(?1,?2,?3,1,1,'linux-executor-v1',9999999999999,?4,?5,?6)",
        params![[11_u8;16].as_slice(),[12_u8;16].as_slice(),[13_u8;16].as_slice(),[14_u8;16].as_slice(),[15_u8;16].as_slice(),[16_u8;16].as_slice()],
    ).unwrap();
    connection.execute(
        "INSERT INTO taskrun_assignment_occupations(taskrun_id,fence,attempt_id,node_id,node_epoch,lease_expires_at_ms,state,dispatch_intent) VALUES(?1,1,?2,?3,1,9999999999999,'active','unknown')",
        params![[11_u8;16].as_slice(),[12_u8;16].as_slice(),[13_u8;16].as_slice()],
    ).unwrap();
    connection.execute("INSERT INTO taskrun_assignments(taskrun_id,attempt_id,node_id,node_epoch,fence,capability_descriptor,lease_expires_at_ms,command_id,admitted_event_id,started_event_id) VALUES(?1,?2,?3,1,1,'linux-executor-v1',9999999999999,?4,?5,?6)", params![[21_u8;16].as_slice(),[22_u8;16].as_slice(),[23_u8;16].as_slice(),[24_u8;16].as_slice(),[25_u8;16].as_slice(),[26_u8;16].as_slice()]).unwrap();
    connection.execute("INSERT INTO taskrun_assignment_occupations(taskrun_id,fence,attempt_id,node_id,node_epoch,lease_expires_at_ms,state,dispatch_intent) VALUES(?1,1,?2,?3,1,9999999999999,'active','present')", params![[21_u8;16].as_slice(),[22_u8;16].as_slice(),[23_u8;16].as_slice()]).unwrap();
    connection.execute("INSERT INTO taskrun_assignments(taskrun_id,attempt_id,node_id,node_epoch,fence,capability_descriptor,lease_expires_at_ms,command_id,admitted_event_id,started_event_id) VALUES(?1,?2,?3,1,1,'linux-executor-v1',9999999999999,?4,?5,?6)", params![[31_u8;16].as_slice(),[32_u8;16].as_slice(),[33_u8;16].as_slice(),[34_u8;16].as_slice(),[35_u8;16].as_slice(),[36_u8;16].as_slice()]).unwrap();
    connection.execute("INSERT INTO taskrun_assignment_occupations(taskrun_id,fence,attempt_id,node_id,node_epoch,lease_expires_at_ms,state,dispatch_intent) VALUES(?1,1,?2,?3,1,9999999999999,'active','absent')", params![[31_u8;16].as_slice(),[32_u8;16].as_slice(),[33_u8;16].as_slice()]).unwrap();
    apply_v44_migration(&connection).unwrap();
    assert!(v43_matches(&connection, 44).unwrap());
    assert!(v44_matches(&connection, 44).unwrap());
    let (occupation, ledger): (String, String) = connection.query_row(
        "SELECT o.dispatch_intent,i.state FROM taskrun_assignment_occupations o JOIN taskrun_dispatch_intents i USING(taskrun_id,fence) WHERE o.taskrun_id=?1 AND o.fence=1",
        [[11_u8;16].as_slice()], |r| Ok((r.get(0)?,r.get(1)?)),
    ).unwrap();
    assert_eq!((occupation.as_str(), ledger.as_str()), ("unknown", "unknown"));
    let (present, absent): (i64, i64) = connection.query_row("SELECT (SELECT COUNT(*) FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND state='present'),(SELECT COUNT(*) FROM taskrun_dispatch_intents WHERE taskrun_id=?2)", params![[21_u8;16].as_slice(),[31_u8;16].as_slice()], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!((present, absent), (1, 0));
    drop(connection);
    let reopened = Connection::open(path).unwrap();
    assert!(classify_existing_connection(&reopened).is_ok());
    assert!(v44_matches(&reopened, 44).unwrap());
    let (occupation, ledger): (String, String) = reopened.query_row(
        "SELECT o.dispatch_intent,i.state FROM taskrun_assignment_occupations o JOIN taskrun_dispatch_intents i USING(taskrun_id,fence) WHERE o.taskrun_id=?1 AND o.fence=1",
        [[11_u8;16].as_slice()], |r| Ok((r.get(0)?,r.get(1)?)),
    ).unwrap();
    assert_eq!((occupation.as_str(), ledger.as_str()), ("unknown", "unknown"));
}

#[test]
fn v44_admission_rejects_removed_evidence_and_drifted_catalog() {
    let connection = v43_database_with_claim();
    apply_v44_migration(&connection).unwrap();
    connection.execute_batch("DROP TRIGGER taskrun_dispatch_intents_no_delete; DELETE FROM taskrun_dispatch_intents;").unwrap();
    assert!(!v44_matches(&connection, 44).unwrap());

    let connection = v43_database_with_claim();
    apply_v44_migration(&connection).unwrap();
    connection.execute_batch("DROP TRIGGER taskrun_occupation_intent_guard;").unwrap();
    assert!(!v44_matches(&connection, 44).unwrap());

    let connection = v43_database_with_claim();
    apply_v44_migration(&connection).unwrap();
    connection.execute_batch("DROP TRIGGER taskrun_occupation_intent_guard; UPDATE taskrun_assignment_occupations SET dispatch_intent='absent';").unwrap();
    assert!(!v44_matches(&connection, 44).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}

#[test]
fn v44_present_occupation_cannot_be_cleared_or_deleted() {
    let connection = v43_database_with_claim();
    apply_v44_migration(&connection).unwrap();
    assert!(connection.execute("UPDATE taskrun_assignment_occupations SET dispatch_intent='absent'", []).is_err());
    assert!(connection.execute("DELETE FROM taskrun_dispatch_intents", []).is_err());
}
