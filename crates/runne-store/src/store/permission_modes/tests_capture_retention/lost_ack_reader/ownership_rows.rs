//! Fixed six-domain projections. No joins, callback, or transaction authority.
use rusqlite::{Connection,Error,Result,Params,types::ValueRef};
pub(super) enum Cell<'a> { Blob(&'a [u8]), Text(&'a [u8]), Integer(i64) }
// SQL is private fixed source below. LIMIT 2 is cardinality, not a scan/heap bound.
fn one<P:Params>(c:&Connection,sql:&str,p:P,want:&[Cell<'_>])->Result<()> {
    let mut s=c.prepare(sql)?;
    if s.column_count()!=want.len() {return Err(Error::InvalidQuery);}
    let mut rows=s.query(p)?;let r=rows.next()?.ok_or(Error::InvalidQuery)?;
    for (n,w) in want.iter().enumerate() {
        let same=match (r.get_ref(n)?,w) {
            (ValueRef::Blob(a),Cell::Blob(b))=>a==*b,
            (ValueRef::Text(a),Cell::Text(b))=>a==*b,
            (ValueRef::Integer(a),Cell::Integer(b))=>a==*b,
            _=>false,
        };
        if !same {return Err(Error::InvalidQuery);}
    }
    if rows.next()?.is_some() {return Err(Error::InvalidQuery);} Ok(())
}
pub(super) fn table(c:&Connection,name:&str)->Result<()> {
    one(c,"SELECT type FROM main.pragma_table_list()
        WHERE schema='main' AND name=?1 LIMIT 2",[name],&[Cell::Text(b"table")])
}
pub(super) fn spent<P:Params>(c:&Connection,p:P,w:&[Cell<'_>])->Result<()> {
    one(c,"SELECT taskrun_id,attempt_id,binding_digest,invocation_id,area_identity,
        owner_id,owner_generation,burn_id,burned_at FROM main.x2_permission_spent
        WHERE (CAST(taskrun_id AS BLOB)=?1 AND CAST(attempt_id AS BLOB)=?2)
        OR CAST(invocation_id AS BLOB)=?3 OR CAST(burn_id AS BLOB)=?4 LIMIT 2",p,w)
}
pub(super) fn settlement<P:Params>(c:&Connection,p:P,w:&[Cell<'_>])->Result<()> {
    one(c,"SELECT taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,
        terminal_version FROM main.taskrun_terminal_settlement_receipts
        WHERE (CAST(taskrun_id AS BLOB)=?1 AND fence=?2)
        OR CAST(terminal_event_id AS BLOB)=?3 LIMIT 2",p,w)
}
pub(super) fn occupation<P:Params>(c:&Connection,p:P,w:&[Cell<'_>])->Result<()> {
    one(c,"SELECT taskrun_id,fence,attempt_id,node_id,node_epoch,lease_expires_at_ms,
        state,dispatch_intent,release_event_id FROM main.taskrun_assignment_occupations
        WHERE (CAST(taskrun_id AS BLOB)=?1 AND fence=?2)
        OR CAST(attempt_id AS BLOB)=?3 OR CAST(release_event_id AS BLOB)=?4 LIMIT 2",p,w)
}
pub(super) fn assignment<P:Params>(c:&Connection,p:P,w:&[Cell<'_>])->Result<()> {
    one(c,"SELECT taskrun_id,attempt_id,node_id,node_epoch,fence,capability_descriptor,
        lease_expires_at_ms,command_id,admitted_event_id,started_event_id
        FROM main.taskrun_assignments
        WHERE (CAST(taskrun_id AS BLOB)=?1 AND fence=?2)
        OR CAST(attempt_id AS BLOB)=?3 OR CAST(command_id AS BLOB)=?4
        OR CAST(admitted_event_id AS BLOB)=?5 OR CAST(started_event_id AS BLOB)=?6 LIMIT 2",p,w)
}
pub(super) fn claim<P:Params>(c:&Connection,p:P,w:&[Cell<'_>])->Result<()> {
    one(c,"SELECT command_id,idempotency_scope_bytes,idempotency_key,fingerprint,
        taskrun_id,attempt_id,node_id,node_epoch,fence,lease_expires_at_ms,new_version,
        admitted_event_id,started_event_id FROM main.taskrun_claim_receipts
        WHERE (CAST(taskrun_id AS BLOB)=?1 AND fence=?2)
        OR CAST(attempt_id AS BLOB)=?3 OR CAST(command_id AS BLOB)=?4
        OR (CAST(idempotency_scope_bytes AS BLOB)=?5 AND CAST(idempotency_key AS BLOB)=?6)
        LIMIT 2",p,w)
}
pub(super) fn attempt<P:Params>(c:&Connection,p:P,w:&[Cell<'_>])->Result<()> {
    one(c,"SELECT taskrun_id,conversation_id,workspace_id,attempt_id,node_id,node_epoch,
        fence,command_digest,managed_area_identity,state,stdout,stderr,exit_code
        FROM main.taskrun_local_command_attempts WHERE CAST(taskrun_id AS BLOB)=?1
        OR CAST(attempt_id AS BLOB)=?2 LIMIT 2",p,w)
}
