//! Copied synthetic V2 row fixture, not a managed factory fixture.
use super::super::super::*;
use rusqlite::params;
pub(super) fn expected()->ownership::Expected<'static> {
    ownership::Expected {invocation:[18;16],area:[2;100],owner:[4;16],generation:[3;8],
        burn:[1;16],burned_at:7,node:[10;16],epoch:3,assignment_lease:500,
        occupation_lease:700,claim_command:[12;16],claim_scope:b"claim-scope",
        claim_key:b"claim-key",claim_fingerprint:[13;32],claim_version:4,
        admitted:[14;16],started:[11;16],conversation:[15;16],workspace:[16;16],
        command_digest:[17;32],attempt_stdout:b"",attempt_stderr:b""}
}
pub(super) fn terminal_fixture()->Connection {
    let c=super::super::super::terminal_tests::fixture();let t=super::super::super::terminal_tests::expected();let e=expected();
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

pub(super) fn pre(burn:[u8;16],time:i64)->Connection {
    let c=terminal_fixture();
    c.execute_batch("PRAGMA query_only=OFF;
        CREATE TABLE saved_terminal AS SELECT * FROM x2_permission_terminal;
        CREATE TABLE saved_settlement AS SELECT * FROM taskrun_terminal_settlement_receipts;
        CREATE TABLE saved_events AS SELECT * FROM events;
        DELETE FROM x2_permission_terminal;DELETE FROM taskrun_terminal_settlement_receipts;
        DELETE FROM events;
        CREATE TABLE _authority(id,authority_id);
        CREATE TABLE _daemon_info(key,value);
        INSERT INTO _daemon_info VALUES('event_log_lineage_id','01010101-0101-7101-8101-010101010101');
        UPDATE taskrun_local_command_attempts SET state='running',exit_code=NULL;").unwrap();
    c.execute("INSERT INTO _authority VALUES(1,?1)",[[42u8;16].as_slice()]).unwrap();
    c.execute("UPDATE x2_permission_spent SET burn_id=?1,burned_at=?2",
        params![burn.as_slice(),time]).unwrap();
    c.execute_batch("PRAGMA query_only=ON").unwrap();c
}
pub(super) fn finish(c:&Connection) {
    c.execute_batch("PRAGMA query_only=OFF;
        INSERT INTO x2_permission_terminal SELECT * FROM saved_terminal;
        INSERT INTO taskrun_terminal_settlement_receipts SELECT * FROM saved_settlement;
        INSERT INTO events SELECT * FROM saved_events;
        UPDATE taskrun_local_command_attempts SET state='completed',exit_code=0;
        PRAGMA query_only=ON").unwrap();
}
