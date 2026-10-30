//! Private single transaction shared by narrow helpers and typed sealed capture.
use super::*;
pub(super) fn capture(
    c:&mut Connection, limits:Limits, intent:Option<&ReceiptIntent<'_>>,
    expected:Option<&terminal::Expected<'_>>, owned:Option<&ownership::Expected<'_>>,
    seal:Option<&burn_observer::Seal<'_>>,
)->Result<(Option<i64>,Snapshot)> {
    if owned.is_some() && (intent.is_none() || expected.is_none()) {
        return Err(Error::InvalidQuery);
    }
    let limits = limits.validate()?;
    let fenced: i64 = c.query_row("PRAGMA query_only",[],|r|r.get(0))?;
    if fenced != 1 || !c.is_autocommit() { return Err(Error::InvalidQuery); }
    let tx = c.transaction()?;
    // The catalog read inside snapshot_in_tx pins the snapshot before receipts.
    // No caller callback or exposed transaction can end/restart this observation.
    let snapshot=snapshot_in_tx(&tx,limits)?;
    if let Some(seal)=seal {
        seal.check_in_tx(&tx,intent.ok_or(Error::InvalidQuery)?,
            expected.ok_or(Error::InvalidQuery)?,owned.ok_or(Error::InvalidQuery)?)?;
    }
    let time=intent.map(|i|receipt_sql::check(&tx,&i.as_receipt())).transpose()?;
    if let Some(e)=expected {
        terminal::check(&tx,intent.ok_or(Error::InvalidQuery)?,e,
            time.ok_or(Error::InvalidQuery)?)?;
    }
    if let Some(o)=owned {
        ownership::check(&tx,intent.ok_or(Error::InvalidQuery)?,
            expected.ok_or(Error::InvalidQuery)?,o)?;
    }
    tx.commit()?;
    Ok((time,snapshot))
}
