//! Fixed receipt query domains only. No transaction/opener/callback authority.
use super::receipt::{self,Intent,Receipt};
use rusqlite::{Connection,Error,Result,Row,types::ValueRef};
fn blob<'a>(row:&'a Row<'_>, n:usize)->Result<&'a [u8]> {
    match row.get_ref(n)? {ValueRef::Blob(v)=>Ok(v),_=>Err(Error::InvalidQuery)}
}
fn integer(row:&Row<'_>,n:usize)->Result<i64> {
    match row.get_ref(n)? {ValueRef::Integer(v)=>Ok(v),_=>Err(Error::InvalidQuery)}
}

fn require_base_table(c:&Connection)->Result<()> {
    let mut statement=c.prepare("SELECT type FROM main.pragma_table_list()
        WHERE schema='main' AND name='command_receipts' LIMIT 2")?;
    let mut rows=statement.query([])?;
    let row=rows.next()?.ok_or(Error::InvalidQuery)?;
    match row.get_ref(0)? {
        ValueRef::Text(kind) if kind==b"table"=>{},
        _=>return Err(Error::InvalidQuery),
    }
    if rows.next()?.is_some() {return Err(Error::InvalidQuery);}
    Ok(())
}

pub(super) fn check(c:&Connection,i:&Intent<'_>)->Result<i64> {
    // Ordinary-table identity is required; matching view results are insufficient.
    require_base_table(c)?;
    // CAST expands the candidate domain to same-byte TEXT aliases. Storage classes
    // are still checked below, never accepted via SQLite affinity coercion.
    // LIMIT 2 distinguishes absent, unique, conflicting; no first-row shortcut.
    let mut statement=c.prepare("SELECT command_id,idempotency_scope_bytes,
        idempotency_key,fingerprint,command_outcome,committed_at
        FROM main.command_receipts WHERE CAST(command_id AS BLOB)=?1 LIMIT 2")?;
    let mut rows=statement.query([i.command.as_slice()])?;
    let row=rows.next()?.ok_or(Error::InvalidQuery)?;
    let record=Receipt {command:blob(row,0)?,scope:blob(row,1)?,key:blob(row,2)?,
        fingerprint:blob(row,3)?,outcome:blob(row,4)?,committed_at:integer(row,5)?};
    receipt::validate(i,&record).map_err(|_|Error::InvalidQuery)?;
    let time=record.committed_at;
    {
        // These bytes have already been independently matched to the frozen intent.
        // Query the whole scope/key conflict domain, not a joined exact-ID subset.
        let mut scoped=c.prepare("SELECT command_id,idempotency_scope_bytes,
            idempotency_key FROM main.command_receipts
            WHERE CAST(idempotency_scope_bytes AS BLOB)=?1
              AND CAST(idempotency_key AS BLOB)=?2 LIMIT 2")?;
        let mut candidates=scoped.query(rusqlite::params![record.scope,record.key])?;
        let found=candidates.next()?.ok_or(Error::InvalidQuery)?;
        if blob(found,0)?!=i.command.as_slice() || blob(found,1)?!=record.scope ||
            blob(found,2)?!=i.key {return Err(Error::InvalidQuery);}
        if candidates.next()?.is_some() {return Err(Error::InvalidQuery);}
    }
    if rows.next()?.is_some() {return Err(Error::InvalidQuery);}
    Ok(time)
}
