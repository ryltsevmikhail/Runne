//! Synthetic unconstrained SQL only, NOT native/migrated history. All NOTRUN.
use super::*;
use rusqlite::params;
pub(super) fn intent()->ReceiptIntent<'static> {
    ReceiptIntent {command:[7;16],task:[9;16],authority:"ra",principal:"p",
        key:b"k",fingerprint:[3;32],version:5}
}
pub(super) fn expected()->terminal::Expected<'static> {
    terminal::Expected {task:[9;16],attempt:[8;16],binding_digest:[6;32],event:[5;16],
        fence:2,stdout:b"out",stderr:b"err",stdout_observed:3,stderr_observed:3,
        actor:b"actor",causation:Some([11;16]),global_position:42,sensitivity:0}
}
pub(super) fn fixture()->Connection {
    let c=super::receipt_transaction_tests::fixture();
    c.execute_batch("PRAGMA query_only=OFF;
        CREATE TABLE x2_permission_terminal(taskrun_id,attempt_id,binding_digest,
        terminal_kind,exit_kind,exit_code,signal,stdout,stderr,stdout_observed,
        stderr_observed,stdout_eof,stderr_eof,stdout_truncated,stderr_truncated,
        area_empty,event_id,fence,terminal_version,settled_at);
        CREATE TABLE events(event_id,aggregate_type,aggregate_id,sequence,global_position,
        timestamp,sensitivity,schema_version,causation_id,command_id,idempotency_key,
        actor,payload,integrity_digest,correlation_id,correlation_type,integrity_profile);
        CREATE TABLE aggregate_streams(aggregate_type,aggregate_id,current_version,
        last_event_id,last_timestamp);").unwrap();
    let e=expected();let i=intent();
    c.execute("INSERT INTO x2_permission_terminal VALUES
        (?1,?2,?3,1,1,0,NULL,?4,?5,3,3,1,1,0,0,1,?6,2,5,11)",
        params![e.task.as_slice(),e.attempt.as_slice(),e.binding_digest.as_slice(),e.stdout,e.stderr,e.event.as_slice()]).unwrap();
    c.execute("INSERT INTO events VALUES
        (?1,1,?2,5,42,11,0,1,?3,?4,?5,?6,X'00010d00',zeroblob(32),?2,1,1)",
        params![e.event.as_slice(),e.task.as_slice(),e.causation.as_ref().map(|v|v.as_slice()),i.command.as_slice(),i.key,e.actor]).unwrap();
    c.execute("INSERT INTO aggregate_streams VALUES(1,?1,5,?2,11)",
        params![e.task.as_slice(),e.event.as_slice()]).unwrap();
    c.execute_batch("PRAGMA query_only=ON").unwrap();c
}
fn observe(c:&mut Connection)->Result<(Option<i64>,Snapshot)> {
    capture_with_terminal(c,Limits::fixture(),Some(&intent()),Some(&expected()))
}
#[test] fn exact_terminal_event_subset_and_snapshot() {
    let mut c=fixture();let (time,first)=observe(&mut c).unwrap();assert_eq!(time,Some(11));
    assert!(c.is_autocommit());assert_eq!(first,capture_connection(&mut c,Limits::fixture()).unwrap());
}
#[test] fn each_terminal_field_mutation_refuses() {
    for mutation in ["stdout=X'00'","stderr=X'00'","stdout_observed=4",
        "stderr_observed=2","stdout_eof=0","stderr_eof=0","stdout_truncated=1",
        "stderr_truncated=1","area_empty=0","exit_code=1","signal=9","exit_kind=2",
        "terminal_kind=2","binding_digest=zeroblob(32)","event_id=zeroblob(16)",
        "fence=3","terminal_version=6","settled_at=12","stdout_observed=3.0"] {
        let mut c=fixture();assert!(observe(&mut c).is_ok());
        c.execute_batch(&format!("PRAGMA query_only=OFF;UPDATE x2_permission_terminal
            SET {mutation};PRAGMA query_only=ON;")).unwrap();
        assert!(observe(&mut c).is_err(),"{mutation}");assert!(c.is_autocommit());
    }
}
#[test] fn each_event_field_mutation_refuses() {
    for mutation in ["payload=X'00060d00'","payload=X'00010d01'","sequence=6",
        "global_position=43","timestamp=12","sensitivity=2","schema_version=2",
        "causation_id=NULL","command_id=zeroblob(16)","idempotency_key=X'78'",
        "actor=X'78'","integrity_digest=zeroblob(31)","integrity_profile=2",
        "correlation_id=zeroblob(16)","correlation_type=2","aggregate_type=2",
        "event_id=CAST(event_id AS TEXT)","timestamp=11.0"] {
        let mut c=fixture();assert!(observe(&mut c).is_ok());
        c.execute_batch(&format!("PRAGMA query_only=OFF;UPDATE events SET {mutation};
            PRAGMA query_only=ON;")).unwrap();assert!(observe(&mut c).is_err(),"{mutation}");
    }
}
#[test] fn terminal_and_event_conflict_domains_refuse() {
    for sql in ["INSERT INTO x2_permission_terminal SELECT * FROM x2_permission_terminal",
        "INSERT INTO x2_permission_terminal SELECT zeroblob(16),zeroblob(16),binding_digest,
        terminal_kind,exit_kind,exit_code,signal,stdout,stderr,stdout_observed,stderr_observed,
        stdout_eof,stderr_eof,stdout_truncated,stderr_truncated,area_empty,event_id,fence,
        terminal_version,settled_at FROM x2_permission_terminal",
        "INSERT INTO events SELECT zeroblob(16),aggregate_type,aggregate_id,sequence,
        global_position,timestamp,sensitivity,schema_version,causation_id,command_id,
        idempotency_key,actor,payload,integrity_digest,correlation_id,correlation_type,
        integrity_profile FROM events"] {
        let mut c=fixture();assert!(observe(&mut c).is_ok());
        c.execute_batch(&format!("PRAGMA query_only=OFF;{sql};PRAGMA query_only=ON;")).unwrap();
        assert!(observe(&mut c).is_err());
    }
}
#[test] fn stream_tail_crosslinks_refuse() {
    for mutation in ["current_version=6","last_event_id=zeroblob(16)","last_timestamp=12",
        "aggregate_type=1.0","aggregate_id=CAST(aggregate_id AS TEXT)"] {
        let mut c=fixture();assert!(observe(&mut c).is_ok());
        c.execute_batch(&format!("PRAGMA query_only=OFF;UPDATE aggregate_streams SET {mutation};
            PRAGMA query_only=ON;")).unwrap();assert!(observe(&mut c).is_err());
    }
}
#[test] fn terminal_view_refuses() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;ALTER TABLE x2_permission_terminal RENAME TO saved_terminal;
        CREATE VIEW x2_permission_terminal AS SELECT * FROM saved_terminal;
        PRAGMA query_only=ON;").unwrap();assert!(observe(&mut c).is_err());
}
#[test] fn invalid_expected_native_facts_refuse() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());let i=intent();let mut e=expected();
    e.stdout_observed=-1;
    assert!(capture_with_terminal(&mut c,Limits::fixture(),Some(&i),Some(&e)).is_err());
    e.stdout_observed=3;e.task=[0;16];
    assert!(capture_with_terminal(&mut c,Limits::fixture(),Some(&i),Some(&e)).is_err());
}
#[test] fn terminal_without_receipt_intent_refuses() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    assert!(capture_with_terminal(&mut c,Limits::fixture(),None,Some(&expected())).is_err());
}
