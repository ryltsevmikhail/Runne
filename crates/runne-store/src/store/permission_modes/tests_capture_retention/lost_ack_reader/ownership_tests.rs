//! Synthetic exact-row continuity only, NOT canonical/native/claim-codec proof.
use super::*;
use rusqlite::params;
fn expected()->ownership::Expected<'static> {
    ownership::Expected {invocation:[18;16],area:[2;100],owner:[4;16],generation:[3;8],
        burn:[1;16],burned_at:7,node:[10;16],epoch:3,assignment_lease:500,
        occupation_lease:700,claim_command:[12;16],claim_scope:b"claim-scope",
        claim_key:b"claim-key",claim_fingerprint:[13;32],claim_version:4,
        admitted:[14;16],started:[11;16],conversation:[15;16],workspace:[16;16],
        command_digest:[17;32],attempt_stdout:b"",attempt_stderr:b""}
}
fn fixture()->Connection {
    let c=super::terminal_tests::fixture();let t=super::terminal_tests::expected();let e=expected();
    c.execute_batch("PRAGMA query_only=OFF;
        CREATE TABLE x2_permission_spent(taskrun_id,attempt_id,binding_digest,invocation_id,
        area_identity,owner_id,owner_generation,burn_id,burned_at);
        CREATE TABLE taskrun_terminal_settlement_receipts(taskrun_id,fence,attempt_id,
        node_id,node_epoch,terminal_event_id,terminal_version);
        CREATE TABLE taskrun_assignment_occupations(taskrun_id,fence,attempt_id,node_id,
        node_epoch,lease_expires_at_ms,state,dispatch_intent,release_event_id);
        CREATE TABLE taskrun_assignments(taskrun_id,attempt_id,node_id,node_epoch,fence,
        capability_descriptor,lease_expires_at_ms,command_id,admitted_event_id,started_event_id);
        CREATE TABLE taskrun_claim_receipts(command_id,idempotency_scope_bytes,idempotency_key,
        fingerprint,taskrun_id,attempt_id,node_id,node_epoch,fence,lease_expires_at_ms,
        new_version,admitted_event_id,started_event_id);
        CREATE TABLE taskrun_local_command_attempts(taskrun_id,conversation_id,workspace_id,
        attempt_id,node_id,node_epoch,fence,command_digest,managed_area_identity,state,
        stdout,stderr,exit_code);").unwrap();
    c.execute("INSERT INTO x2_permission_spent VALUES(?1,?2,?3,?4,?5,?6,?7,?8,7)",
        params![t.task.as_slice(),t.attempt.as_slice(),t.binding_digest.as_slice(),e.invocation.as_slice(),
        e.area.as_slice(),e.owner.as_slice(),e.generation.as_slice(),e.burn.as_slice()]).unwrap();
    c.execute("INSERT INTO taskrun_terminal_settlement_receipts VALUES(?1,2,?2,?3,3,?4,5)",
        params![t.task.as_slice(),t.attempt.as_slice(),e.node.as_slice(),t.event.as_slice()]).unwrap();
    c.execute("INSERT INTO taskrun_assignment_occupations VALUES(?1,2,?2,?3,3,700,'released','absent',?4)",
        params![t.task.as_slice(),t.attempt.as_slice(),e.node.as_slice(),t.event.as_slice()]).unwrap();
    c.execute("INSERT INTO taskrun_assignments VALUES(?1,?2,?3,3,2,'linux-executor-v1',500,?4,?5,?6)",
        params![t.task.as_slice(),t.attempt.as_slice(),e.node.as_slice(),e.claim_command.as_slice(),
        e.admitted.as_slice(),e.started.as_slice()]).unwrap();
    c.execute("INSERT INTO taskrun_claim_receipts VALUES(?1,?2,?3,?4,?5,?6,?7,3,2,500,4,?8,?9)",
        params![e.claim_command.as_slice(),e.claim_scope,e.claim_key,e.claim_fingerprint.as_slice(),
        t.task.as_slice(),t.attempt.as_slice(),e.node.as_slice(),e.admitted.as_slice(),e.started.as_slice()]).unwrap();
    c.execute("INSERT INTO taskrun_local_command_attempts VALUES(?1,?2,?3,?4,?5,3,2,?6,?7,'completed',X'',X'',0)",
        params![t.task.as_slice(),e.conversation.as_slice(),e.workspace.as_slice(),t.attempt.as_slice(),
        e.node.as_slice(),e.command_digest.as_slice(),e.area.as_slice()]).unwrap();
    c.execute_batch("PRAGMA query_only=ON").unwrap();c
}
fn observe(c:&mut Connection)->Result<(Option<i64>,Snapshot)> {
    capture_with_ownership(c,Limits::fixture(),Some(&super::terminal_tests::intent()),
        Some(&super::terminal_tests::expected()),Some(&expected()))
}
#[test] fn all_six_domains_and_independent_leases_match() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());assert!(c.is_autocommit());
    // occupation lease700 intentionally differs from immutable assignment/claim500.
}
#[test] fn each_domain_field_mutation_refuses() {
    for (table,mutation) in [
        ("x2_permission_spent","invocation_id=zeroblob(16)"),
        ("x2_permission_spent","area_identity=zeroblob(100)"),
        ("x2_permission_spent","owner_id=zeroblob(16)"),
        ("x2_permission_spent","owner_generation=zeroblob(8)"),
        ("x2_permission_spent","burn_id=zeroblob(16)"),("x2_permission_spent","burned_at=8"),
        ("taskrun_terminal_settlement_receipts","terminal_version=6"),
        ("taskrun_terminal_settlement_receipts","node_epoch=4"),
        ("taskrun_assignment_occupations","state='active'"),
        ("taskrun_assignment_occupations","dispatch_intent='present'"),
        ("taskrun_assignment_occupations","lease_expires_at_ms=500"),
        ("taskrun_assignment_occupations","release_event_id=NULL"),
        ("taskrun_assignments","capability_descriptor='other'"),
        ("taskrun_assignments","admitted_event_id=zeroblob(16)"),
        ("taskrun_assignments","command_id=zeroblob(16)"),
        ("taskrun_claim_receipts","fingerprint=zeroblob(32)"),
        ("taskrun_claim_receipts","idempotency_scope_bytes=X'00'"),
        ("taskrun_claim_receipts","new_version=5"),
        ("taskrun_local_command_attempts","state='running'"),
        ("taskrun_local_command_attempts","exit_code=1"),
        ("taskrun_local_command_attempts","stdout=X'6f7574'"),
        ("taskrun_local_command_attempts","fence=2.0")] {
        let mut c=fixture();assert!(observe(&mut c).is_ok());
        c.execute_batch(&format!("PRAGMA query_only=OFF;UPDATE {table} SET {mutation};
            PRAGMA query_only=ON;")).unwrap();assert!(observe(&mut c).is_err(),"{table}:{mutation}");
    }
}
#[test] fn missing_or_duplicate_domain_refuses() {
    for table in ["x2_permission_spent","taskrun_terminal_settlement_receipts",
        "taskrun_assignment_occupations","taskrun_assignments","taskrun_claim_receipts",
        "taskrun_local_command_attempts"] {
        for duplicate in [false,true] {
            let mut c=fixture();assert!(observe(&mut c).is_ok());
            let sql=if duplicate {format!("INSERT INTO {table} SELECT * FROM {table}")}
                else {format!("DELETE FROM {table}")};
            c.execute_batch(&format!("PRAGMA query_only=OFF;{sql};PRAGMA query_only=ON;")).unwrap();
            assert!(observe(&mut c).is_err());assert!(c.is_autocommit());
        }
    }
}
#[test] fn cross_task_invocation_and_burn_collisions_refuse() {
    for column in ["invocation_id","burn_id"] {
        let mut c=fixture();assert!(observe(&mut c).is_ok());
        c.execute_batch(&format!("PRAGMA query_only=OFF;INSERT INTO x2_permission_spent
            SELECT zeroblob(16),zeroblob(16),binding_digest,invocation_id,area_identity,
            owner_id,owner_generation,burn_id,burned_at FROM x2_permission_spent;
            UPDATE x2_permission_spent SET {}=zeroblob(16) WHERE taskrun_id=zeroblob(16);
            PRAGMA query_only=ON;",if column=="invocation_id" {"burn_id"}else{"invocation_id"})).unwrap();
        assert!(observe(&mut c).is_err());
    }
}
#[test] fn invalid_preterminal_facts_refuse() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());let mut e=expected();e.burned_at=0;
    assert!(capture_with_ownership(&mut c,Limits::fixture(),Some(&super::terminal_tests::intent()),
        Some(&super::terminal_tests::expected()),Some(&e)).is_err());
}
#[test] fn ownership_without_terminal_facts_refuses() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    assert!(capture_with_ownership(&mut c,Limits::fixture(),Some(&super::terminal_tests::intent()),
        None,Some(&expected())).is_err());
}

#[test] fn coordinated_claim_version_refuses() {
    for version in [1,5,6] {
        let mut c=fixture();assert!(observe(&mut c).is_ok());let mut e=expected();
        e.claim_version=version;
        c.execute_batch(&format!("PRAGMA query_only=OFF;UPDATE taskrun_claim_receipts
            SET new_version={version};PRAGMA query_only=ON;")).unwrap();
        assert!(capture_with_ownership(&mut c,Limits::fixture(),Some(&super::terminal_tests::intent()),
            Some(&super::terminal_tests::expected()),Some(&e)).is_err());
    }
}
#[test] fn coordinated_event_roles_refuse() {
    for role in [0,1,2] {
        let mut c=fixture();assert!(observe(&mut c).is_ok());let mut e=expected();
        let terminal=super::terminal_tests::expected();
        if role==0 {e.started=e.admitted;} else if role==1 {e.admitted=terminal.event;}
        else {e.started=terminal.event;}
        c.execute_batch("PRAGMA query_only=OFF;").unwrap();
        for table in ["taskrun_assignments","taskrun_claim_receipts"] {
            c.execute(&format!("UPDATE {table} SET admitted_event_id=?1,started_event_id=?2"),
                params![e.admitted.as_slice(),e.started.as_slice()]).unwrap();
        }
        c.execute_batch("PRAGMA query_only=ON;").unwrap();
        assert!(capture_with_ownership(&mut c,Limits::fixture(),Some(&super::terminal_tests::intent()),
            Some(&terminal),Some(&e)).is_err());
    }
}
#[test] fn coordinated_claim_completion_command_refuses() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());let mut e=expected();
    let intent=super::terminal_tests::intent();e.claim_command=intent.command;
    c.execute_batch("PRAGMA query_only=OFF;").unwrap();
    for table in ["taskrun_assignments","taskrun_claim_receipts"] {
        c.execute(&format!("UPDATE {table} SET command_id=?1"),[e.claim_command.as_slice()]).unwrap();
    }
    c.execute_batch("PRAGMA query_only=ON;").unwrap();
    assert!(capture_with_ownership(&mut c,Limits::fixture(),Some(&intent),
        Some(&super::terminal_tests::expected()),Some(&e)).is_err());
}
