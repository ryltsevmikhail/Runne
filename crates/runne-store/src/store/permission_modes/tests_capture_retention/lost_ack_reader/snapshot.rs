//! Fresh-fixture logical snapshot and typed burn Reader; execution NOTRUN.
//! No migration, trust creation, GO, recovery or abort authority.
use crate::schema::ManagedConnection;
use rusqlite::{Connection, Error, Result, Row, types::ValueRef};
#[path="receipt.rs"]
mod receipt;
#[path="receipt_sql.rs"]
mod receipt_sql;
#[path="terminal.rs"]
pub(super) mod terminal;
#[path="ownership.rs"]
pub(super) mod ownership;
#[path="ownership_rows.rs"]
mod ownership_rows;

#[path="capture_core.rs"]
mod capture_core;
#[path="burn_observer.rs"]
pub(super) mod burn_observer;

#[derive(PartialEq,Eq)]
// Test-only input; caller must freeze it before original commit.
pub(super) struct ReceiptIntent<'a> {
    pub command: [u8;16], pub task: [u8;16],
    pub authority: &'a str, pub principal: &'a str, pub key: &'a [u8],
    pub fingerprint: [u8;32], pub version: u64,
}
impl ReceiptIntent<'_> {
    fn as_receipt(&self) -> receipt::Intent<'_> {
        receipt::Intent {command:self.command,task:self.task,authority:self.authority,
            principal:self.principal,key:self.key,fingerprint:self.fingerprint,
            version:self.version}
    }
}

// Receipt-only semantics plus full snapshot; NOT full terminal/native oracle.
pub(super) fn capture_receipt_checked(
    reader: &mut ManagedConnection, intent: &ReceiptIntent<'_>,
) -> Result<(i64,Snapshot)> {
    reader.verify_retained_identity()?;
    let result=reader.with_connection_mut(|c|
        capture_checked_connection(c,Limits::fixture(),Some(intent)));
    reader.verify_retained_identity()?;
    let (time,snapshot)=result?;
    Ok((time.ok_or(Error::InvalidQuery)?,snapshot))
}

#[derive(Clone, Copy)]
struct Limits {
    tables: usize,
    rows: usize,
    columns: usize,
    bytes: usize,
}
impl Limits {
    fn fixture() -> Self {
        Self { tables: 1024, rows: 16384, columns: 256, bytes: 4*1024*1024 }
    }
    fn validate(self) -> Result<Self> {
        let cap = Self::fixture();
        if self.tables > cap.tables || self.rows > cap.rows ||
            self.columns > cap.columns || self.bytes > cap.bytes {
            return Err(Error::InvalidQuery);
        }
        Ok(self)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    user_version: i64,
    application_id: i64,
    catalog: Vec<Vec<u8>>,
    tables: Vec<(String, Vec<Vec<u8>>)>,
}

struct Budget {
    limits: Limits,
    bytes: usize,
    rows: usize,
}
impl Budget {
    fn bytes(&mut self, count: usize) -> Result<()> {
        self.bytes = self.bytes.checked_add(count).ok_or(Error::InvalidQuery)?;
        if self.bytes > self.limits.bytes { return Err(Error::InvalidQuery); }
        Ok(())
    }
    fn row(&mut self) -> Result<()> {
        self.rows = self.rows.checked_add(1).ok_or(Error::InvalidQuery)?;
        if self.rows > self.limits.rows { return Err(Error::InvalidQuery); }
        Ok(())
    }
}

// The managed opener/authority/lineage and independent process are caller gates.
// query_only is a checked SQL fence, NOT proof of O_RDONLY or authenticated role.
pub(super) fn capture(reader: &mut ManagedConnection) -> Result<Snapshot> {
    reader.verify_retained_identity()?;
    let result = reader.with_connection_mut(|c| capture_connection(c, Limits::fixture()));
    reader.verify_retained_identity()?;
    result
}

fn append(out: &mut Vec<u8>, data: &[u8], budget: &mut Budget) -> Result<()> {
    budget.bytes(data.len())?;
    out.extend_from_slice(data);
    Ok(())
}

// Length-delimited exact storage classes; preserves arbitrary TEXT bytes and REAL bits.
fn encode(row: &Row<'_>, columns: usize, budget: &mut Budget) -> Result<Vec<u8>> {
    budget.row()?;
    if columns > budget.limits.columns { return Err(Error::InvalidQuery); }
    let mut out = Vec::new();
    append(&mut out,&u32::try_from(columns).map_err(|_| Error::InvalidQuery)?.to_be_bytes(),budget)?;
    for column in 0..columns {
        match row.get_ref(column)? {
            ValueRef::Null => append(&mut out,&[0],budget)?,
            ValueRef::Integer(value) => {
                append(&mut out,&[1],budget)?;
                append(&mut out,&value.to_be_bytes(),budget)?;
            }
            ValueRef::Real(value) => {
                append(&mut out,&[2],budget)?;
                append(&mut out,&value.to_bits().to_be_bytes(),budget)?;
            }
            ValueRef::Text(data) | ValueRef::Blob(data) => {
                let tag = if matches!(row.get_ref(column)?,ValueRef::Text(_)) {3} else {4};
                append(&mut out,&[tag],budget)?;
                let len = u32::try_from(data.len()).map_err(|_| Error::InvalidQuery)?;
                append(&mut out,&len.to_be_bytes(),budget)?;
                append(&mut out,data,budget)?;
            }
        }
    }
    Ok(out)
}

fn quoted(name: &str) -> Result<String> {
    if name.is_empty() || name.len() > 256 || name.contains('\0') {
        return Err(Error::InvalidQuery);
    }
    Ok(format!("\"{}\"",name.replace('"',"\"\"")))
}

fn table_rows(c: &Connection, name: &str, budget: &mut Budget) -> Result<Vec<Vec<u8>>> {
    let (kind,without_rowid): (String,i64) = c.query_row(
        "SELECT type,wr FROM main.pragma_table_list() WHERE schema='main' AND name=?1",
        [name],|r|Ok((r.get(0)?,r.get(1)?)))?;
    // No virtual/shadow-table side effects or guessed WITHOUT ROWID fallback.
    if kind != "table" || !matches!(without_rowid,0|1) { return Err(Error::InvalidQuery); }
    let name = quoted(name)?;
    let plain = format!("SELECT * FROM main.{name}");
    let metadata = c.prepare(&plain)?;
    let alias = if without_rowid == 0 {
        Some(["rowid","_rowid_","oid"].into_iter().find(|alias| {
            !metadata.column_names().iter().any(|column|column.eq_ignore_ascii_case(alias))
        }).ok_or(Error::InvalidQuery)?)
    } else { None };
    drop(metadata);
    let sql = match alias {
        Some(alias) => format!("SELECT {alias},* FROM main.{name}"),
        None => plain,
    };
    let mut statement = c.prepare(&sql)?;
    let columns = statement.column_count();
    if columns > budget.limits.columns { return Err(Error::InvalidQuery); }
    let mut query = statement.query([])?;
    let mut rows = Vec::new();
    while let Some(row) = query.next()? {
        rows.push(encode(row,columns,budget)?);
    }
    rows.sort(); // retain duplicates and row identity, ignore retrieval order only
    Ok(rows)
}

fn capture_connection(c: &mut Connection, limits: Limits) -> Result<Snapshot> {
    capture_checked_connection(c,limits,None).map(|(_,snapshot)|snapshot)
}

fn capture_checked_connection(
    c: &mut Connection, limits: Limits, intent: Option<&ReceiptIntent<'_>>,
) -> Result<(Option<i64>,Snapshot)> {
    capture_with_terminal(c,limits,intent,None)
}

fn capture_with_terminal(
    c: &mut Connection, limits: Limits, intent: Option<&ReceiptIntent<'_>>,
    expected:Option<&terminal::Expected<'_>>,
) -> Result<(Option<i64>,Snapshot)> {
    capture_with_ownership(c,limits,intent,expected,None)
}

fn capture_with_ownership(
    c:&mut Connection, limits:Limits, intent:Option<&ReceiptIntent<'_>>,
    expected:Option<&terminal::Expected<'_>>, owned:Option<&ownership::Expected<'_>>,
)->Result<(Option<i64>,Snapshot)> {
    capture_core::capture(c,limits,intent,expected,owned,None)
}

fn snapshot_in_tx(c: &Connection, limits: Limits) -> Result<Snapshot> {
    let mut budget = Budget { limits, bytes: 0, rows: 0 };
    let mut catalog = Vec::new();
    let mut names = Vec::new();
    {
        // First read establishes the single SQLite read snapshot before all rows/PRAGMAs.
        let mut statement = c.prepare("SELECT type,name,tbl_name,sql FROM main.sqlite_schema")?;
        let mut query = statement.query([])?;
        while let Some(row) = query.next()? {
            let encoded = encode(row,4,&mut budget)?;
            if row.get_ref(0)?.as_str().map_err(|_| Error::InvalidQuery)? == "table" {
                if names.len() >= limits.tables { return Err(Error::InvalidQuery); }
                let name = row.get_ref(1)?.as_str().map_err(|_| Error::InvalidQuery)?;
                quoted(name)?;
                // A second owned table-name copy is charged, not hidden in catalog cost.
                budget.bytes(name.len())?;
                names.push(name.to_owned());
            }
            catalog.push(encoded);
        }
    }
    catalog.sort();names.sort();
    let user_version = c.query_row("PRAGMA user_version",[],|r|r.get(0))?;
    let application_id = c.query_row("PRAGMA application_id",[],|r|r.get(0))?;
    let mut tables = Vec::new();
    for name in names {
        let rows = table_rows(c,&name,&mut budget)?;
        tables.push((name,rows));
    }
    Ok(Snapshot { user_version, application_id, catalog, tables })
}

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod tests;

#[cfg(test)]
#[path="receipt_transaction_tests.rs"]
mod receipt_transaction_tests;

// Subset check only: does not authorize abort/recovery or qualify full history.
pub(super) fn capture_terminal_checked(
    reader:&mut ManagedConnection, intent:&ReceiptIntent<'_>, expected:&terminal::Expected<'_>,
)->Result<(i64,Snapshot)> {
    reader.verify_retained_identity()?;
    let result=reader.with_connection_mut(|c|
        capture_with_terminal(c,Limits::fixture(),Some(intent),Some(expected)));
    reader.verify_retained_identity()?;
    let (time,snapshot)=result?;
    Ok((time.ok_or(Error::InvalidQuery)?,snapshot))
}
#[cfg(test)]
#[path="terminal_tests.rs"]
mod terminal_tests;

// Same private transaction, independently retained inputs, no callback.
pub(super) fn capture_ownership_checked(
    reader:&mut ManagedConnection, intent:&ReceiptIntent<'_>,
    terminal:&terminal::Expected<'_>, owned:&ownership::Expected<'_>,
)->Result<(i64,Snapshot)> {
    reader.verify_retained_identity()?;
    let result=reader.with_connection_mut(|c|
        capture_with_ownership(c,Limits::fixture(),Some(intent),Some(terminal),Some(owned)));
    reader.verify_retained_identity()?;
    let (time,snapshot)=result?;
    Ok((time.ok_or(Error::InvalidQuery)?,snapshot))
}
#[cfg(test)]
#[path="ownership_tests.rs"]
mod ownership_tests;
