//! Success terminal/event SUBSET oracle; not native proof or integrity replay.
use super::ReceiptIntent;
use rusqlite::{Connection,Error,Result,Row,params,types::ValueRef};
// All expected values must originate independently of committed rows under test.
#[derive(PartialEq,Eq)]
pub(crate) struct Expected<'a> {
    pub task:[u8;16], pub attempt:[u8;16], pub binding_digest:[u8;32],
    pub event:[u8;16], pub fence:i64, pub stdout:&'a [u8], pub stderr:&'a [u8],
    pub stdout_observed:i64, pub stderr_observed:i64, pub actor:&'a [u8],
    pub causation:Option<[u8;16]>, pub global_position:i64, pub sensitivity:i64,
}
fn blob<'a>(r:&'a Row<'_>,n:usize)->Result<&'a [u8]> {
    match r.get_ref(n)? {ValueRef::Blob(v)=>Ok(v),_=>Err(Error::InvalidQuery)}
}
fn integer(r:&Row<'_>,n:usize)->Result<i64> {
    match r.get_ref(n)? {ValueRef::Integer(v)=>Ok(v),_=>Err(Error::InvalidQuery)}
}
fn same_blob(r:&Row<'_>,n:usize,want:&[u8])->Result<()> {
    if blob(r,n)?!=want {return Err(Error::InvalidQuery);} Ok(())
}
fn integers(r:&Row<'_>,expected:&[(usize,i64)])->Result<()> {
    for &(n,want) in expected {
        if integer(r,n)?!=want {return Err(Error::InvalidQuery);}
    } Ok(())
}
fn table(c:&Connection,name:&str)->Result<()> {
    let mut s=c.prepare("SELECT type FROM main.pragma_table_list()
        WHERE schema='main' AND name=?1 LIMIT 2")?;
    let mut rows=s.query([name])?;let r=rows.next()?.ok_or(Error::InvalidQuery)?;
    match r.get_ref(0)? {ValueRef::Text(v) if v==b"table"=>{},_=>return Err(Error::InvalidQuery)}
    if rows.next()?.is_some() {return Err(Error::InvalidQuery);} Ok(())
}
fn unique_identity(c:&Connection,sql:&str,key:&[u8],expected:&[&[u8]])->Result<()> {
    // sql is private and called ONLY with the two fixed literal projections below.
    let mut s=c.prepare(sql)?;let mut rows=s.query([key])?;
    let r=rows.next()?.ok_or(Error::InvalidQuery)?;
    for (n,want) in expected.iter().enumerate() {same_blob(r,n,want)?;}
    if rows.next()?.is_some() {return Err(Error::InvalidQuery);} Ok(())
}
pub(super) fn check(c:&Connection,i:&ReceiptIntent<'_>,e:&Expected<'_>,time:i64)->Result<()> {
    if e.task!=i.task || e.fence<=0 || time<=0 || e.global_position<=0 ||
        e.actor.is_empty() || e.actor.len()>256 || !matches!(e.sensitivity,0|2) ||
        e.stdout.len()>65536 || e.stderr.len()>65536 ||
        e.stdout_observed<i64::try_from(e.stdout.len()).map_err(|_|Error::InvalidQuery)? ||
        e.stderr_observed<i64::try_from(e.stderr.len()).map_err(|_|Error::InvalidQuery)? {
        return Err(Error::InvalidQuery);
    }
    table(c,"x2_permission_terminal")?;table(c,"events")?;table(c,"aggregate_streams")?;
    terminal(c,i,e,time)?;event(c,i,e,time)?;stream(c,i,e,time)
}
fn terminal(c:&Connection,i:&ReceiptIntent<'_>,e:&Expected<'_>,time:i64)->Result<()> {
    let mut s=c.prepare("SELECT taskrun_id,attempt_id,binding_digest,terminal_kind,
        exit_kind,exit_code,signal,stdout,stderr,stdout_observed,stderr_observed,
        stdout_eof,stderr_eof,stdout_truncated,stderr_truncated,area_empty,event_id,
        fence,terminal_version,settled_at FROM main.x2_permission_terminal
        WHERE CAST(taskrun_id AS BLOB)=?1 AND CAST(attempt_id AS BLOB)=?2 LIMIT 2")?;
    let mut rows=s.query(params![e.task.as_slice(),e.attempt.as_slice()])?;
    let r=rows.next()?.ok_or(Error::InvalidQuery)?;
    for (n,want) in [(0,e.task.as_slice()),(1,e.attempt.as_slice()),
        (2,e.binding_digest.as_slice()),(7,e.stdout),(8,e.stderr),(16,e.event.as_slice())] {
        same_blob(r,n,want)?;
    }
    if !matches!(r.get_ref(6)?,ValueRef::Null) {return Err(Error::InvalidQuery);}
    integers(r,&[(3,1),(4,1),(5,0),(9,e.stdout_observed),(10,e.stderr_observed),
        (11,1),(12,1),(13,if e.stdout_observed>e.stdout.len() as i64 {1}else{0}),
        (14,if e.stderr_observed>e.stderr.len() as i64 {1}else{0}),(15,1),
        (17,e.fence),(18,i64::try_from(i.version).map_err(|_|Error::InvalidQuery)?),(19,time)])?;
    if rows.next()?.is_some() {return Err(Error::InvalidQuery);}
    unique_identity(c,"SELECT taskrun_id,attempt_id FROM main.x2_permission_terminal
        WHERE CAST(event_id AS BLOB)=?1 LIMIT 2",&e.event,&[&e.task,&e.attempt])
}
fn event(c:&Connection,i:&ReceiptIntent<'_>,e:&Expected<'_>,time:i64)->Result<()> {
    let mut s=c.prepare("SELECT event_id,aggregate_type,aggregate_id,sequence,
        global_position,timestamp,sensitivity,schema_version,causation_id,command_id,
        idempotency_key,actor,payload,integrity_digest,correlation_id,correlation_type,
        integrity_profile FROM main.events WHERE CAST(event_id AS BLOB)=?1 LIMIT 2")?;
    let mut rows=s.query([e.event.as_slice()])?;let r=rows.next()?.ok_or(Error::InvalidQuery)?;
    for (n,want) in [(0,e.event.as_slice()),(2,e.task.as_slice()),(9,i.command.as_slice()),
        (10,i.key),(11,e.actor),(12,&[0,1,0x0d,0][..]),(14,e.task.as_slice())] {
        same_blob(r,n,want)?;
    }
    match (&e.causation,r.get_ref(8)?) {
        (None,ValueRef::Null)=>{},
        (Some(want),ValueRef::Blob(actual)) if actual==want.as_slice()=>{},
        _=>return Err(Error::InvalidQuery),
    }
    // Digest storage shape ONLY. Full hash validation/replay is still mandatory.
    if blob(r,13)?.len()!=32 {return Err(Error::InvalidQuery);}
    integers(r,&[(1,1),(3,i64::try_from(i.version).map_err(|_|Error::InvalidQuery)?),
        (4,e.global_position),(5,time),(6,e.sensitivity),(7,1),(15,1),(16,1)])?;
    if rows.next()?.is_some() {return Err(Error::InvalidQuery);}
    unique_identity(c,"SELECT event_id FROM main.events
        WHERE CAST(command_id AS BLOB)=?1 LIMIT 2",&i.command,&[&e.event])
}
fn stream(c:&Connection,i:&ReceiptIntent<'_>,e:&Expected<'_>,time:i64)->Result<()> {
    let mut s=c.prepare("SELECT aggregate_type,aggregate_id,current_version,last_event_id,
        last_timestamp FROM main.aggregate_streams WHERE aggregate_type=1
        AND CAST(aggregate_id AS BLOB)=?1 LIMIT 2")?;
    let mut rows=s.query([e.task.as_slice()])?;let r=rows.next()?.ok_or(Error::InvalidQuery)?;
    same_blob(r,1,&e.task)?;same_blob(r,3,&e.event)?;
    integers(r,&[(0,1),(2,i64::try_from(i.version).map_err(|_|Error::InvalidQuery)?),(4,time)])?;
    if rows.next()?.is_some() {return Err(Error::InvalidQuery);} Ok(())
}
