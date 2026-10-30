//! Private fixed SQL. LIMIT 2 controls cardinality, not scan/heap/WAL/deadline cost.
use super::{OriginalFacts,ownership_rows};
use ownership_rows::Cell::{Blob as B,Integer as I};
use rusqlite::{Connection,Error,Result,Row,params,types::ValueRef};
use runne_domain::id::validate_uuid_v7_bytes;
fn blob<'a>(r:&'a Row<'_>,n:usize)->Result<&'a [u8]> {
    match r.get_ref(n)? {ValueRef::Blob(b)=>Ok(b),_=>Err(Error::InvalidQuery)}
}
fn integer(r:&Row<'_>,n:usize)->Result<i64> {
    match r.get_ref(n)? {ValueRef::Integer(v)=>Ok(v),_=>Err(Error::InvalidQuery)}
}
pub(super) fn identity(c:&Connection,f:&OriginalFacts<'_>)->Result<()> {
    f.validate()?;
    ownership_rows::table(c,"_authority")?;ownership_rows::table(c,"_daemon_info")?;
    {
        let mut s=c.prepare("SELECT id,authority_id FROM main._authority LIMIT 2")?;
        let mut q=s.query([])?;let r=q.next()?.ok_or(Error::InvalidQuery)?;
        if integer(r,0)?!=1 || blob(r,1)?!=f.authority.as_slice() ||
            q.next()?.is_some() {return Err(Error::InvalidQuery);}
    }
    let mut s=c.prepare("SELECT key,value FROM main._daemon_info
        WHERE CAST(key AS BLOB)=?1 LIMIT 2")?;
    let mut q=s.query([b"event_log_lineage_id".as_slice()])?;
    let r=q.next()?.ok_or(Error::InvalidQuery)?;
    match (r.get_ref(0)?,r.get_ref(1)?) {
        (ValueRef::Text(k),ValueRef::Text(v)) if k==b"event_log_lineage_id" &&
            v==f.lineage.to_string().as_bytes()=>{},
        _=>return Err(Error::InvalidQuery),
    }
    if q.next()?.is_some() {return Err(Error::InvalidQuery);} Ok(())
}
pub(super) fn spent(c:&Connection,f:&OriginalFacts<'_>,burn:[u8;16],time:i64)->Result<()> {
    ownership_rows::table(c,"x2_permission_spent")?;
    let t=&f.terminal;let e=&f.ownership;
    ownership_rows::spent(c,params![t.task.as_slice(),t.attempt.as_slice(),
        e.invocation.as_slice(),burn.as_slice()],&[B(&t.task),B(&t.attempt),
        B(&t.binding_digest),B(&e.invocation),B(&e.area),B(&e.owner),B(&e.generation),
        B(&burn),I(time)])
}
pub(super) fn read_spent(c:&Connection,f:&OriginalFacts<'_>)->Result<([u8;16],i64)> {
    ownership_rows::table(c,"x2_permission_spent")?;
    let t=&f.terminal;
    let (burn,time)={
        let mut s=c.prepare("SELECT burn_id,burned_at FROM main.x2_permission_spent
            WHERE (CAST(taskrun_id AS BLOB)=?1 AND CAST(attempt_id AS BLOB)=?2)
            OR CAST(invocation_id AS BLOB)=?3 LIMIT 2")?;
        let mut q=s.query(params![t.task.as_slice(),t.attempt.as_slice(),
            f.ownership.invocation.as_slice()])?;
        let r=q.next()?.ok_or(Error::InvalidQuery)?;
        let burn:[u8;16]=blob(r,0)?.try_into().map_err(|_|Error::InvalidQuery)?;
        let time=integer(r,1)?;
        if burn==[0;16] || time<=0 || q.next()?.is_some() {return Err(Error::InvalidQuery);}
        validate_uuid_v7_bytes(&burn).map_err(|_|Error::InvalidQuery)?;
        (burn,time)
    };
    // Independent original facts plus reverse burn domain, all in the same private tx.
    spent(c,f,burn,time)?;Ok((burn,time))
}
pub(super) fn preterminal(c:&Connection,f:&OriginalFacts<'_>)->Result<()> {
    for name in ["x2_permission_terminal","taskrun_terminal_settlement_receipts",
        "events","taskrun_local_command_attempts"] {ownership_rows::table(c,name)?;}
    let t=&f.terminal;let e=&f.ownership;
    {
        let mut s=c.prepare("SELECT 1 FROM main.x2_permission_terminal
            WHERE CAST(taskrun_id AS BLOB)=?1 OR CAST(attempt_id AS BLOB)=?2
            OR CAST(event_id AS BLOB)=?3 LIMIT 1")?;
        if s.query(params![t.task.as_slice(),t.attempt.as_slice(),t.event.as_slice()])?
            .next()?.is_some() {return Err(Error::InvalidQuery);}
    }
    {
        let mut s=c.prepare("SELECT 1 FROM main.taskrun_terminal_settlement_receipts
            WHERE CAST(taskrun_id AS BLOB)=?1 OR CAST(attempt_id AS BLOB)=?2
            OR CAST(terminal_event_id AS BLOB)=?3 LIMIT 1")?;
        if s.query(params![t.task.as_slice(),t.attempt.as_slice(),t.event.as_slice()])?
            .next()?.is_some() {return Err(Error::InvalidQuery);}
    }
    {
        let mut s=c.prepare("SELECT 1 FROM main.events WHERE CAST(event_id AS BLOB)=?1
            OR CAST(command_id AS BLOB)=?2 LIMIT 1")?;
        if s.query(params![t.event.as_slice(),f.intent.command.as_slice()])?
            .next()?.is_some() {return Err(Error::InvalidQuery);}
    }
    let mut s=c.prepare("SELECT taskrun_id,conversation_id,workspace_id,attempt_id,
        node_id,node_epoch,fence,command_digest,managed_area_identity,state,stdout,stderr,
        exit_code FROM main.taskrun_local_command_attempts
        WHERE CAST(taskrun_id AS BLOB)=?1 OR CAST(attempt_id AS BLOB)=?2 LIMIT 2")?;
    let mut q=s.query(params![t.task.as_slice(),t.attempt.as_slice()])?;
    let r=q.next()?.ok_or(Error::InvalidQuery)?;
    for (n,want) in [(0,t.task.as_slice()),(1,e.conversation.as_slice()),
        (2,e.workspace.as_slice()),(3,t.attempt.as_slice()),(4,e.node.as_slice()),
        (7,e.command_digest.as_slice()),(8,e.area.as_slice()),
        (10,e.attempt_stdout),(11,e.attempt_stderr)] {
        if blob(r,n)?!=want {return Err(Error::InvalidQuery);}
    }
    if integer(r,5)?!=e.epoch || integer(r,6)?!=t.fence ||
        !matches!(r.get_ref(9)?,ValueRef::Text(b) if b==b"running") ||
        !matches!(r.get_ref(12)?,ValueRef::Null) || q.next()?.is_some() {
        return Err(Error::InvalidQuery);
    }
    Ok(())
}
