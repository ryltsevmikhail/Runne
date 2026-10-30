//! Concrete managed Reader continuity, SOURCE_ONLY / NOTRUN.
//! A preterminal read cut is NOT a C-held-before-W-commit protocol barrier.
use super::{capture_core,ownership,ownership_rows,terminal,ReceiptIntent,Limits,Snapshot};
use crate::schema::{ManagedConnection,ConnectionMode,reopen_managed_connection_validated};
use rusqlite::{Connection,Error,Result};
use std::path::Path;
#[path="burn_context.rs"]
mod context;
pub(in super::super) use context::{Context,OriginalFacts};
#[path="burn_rows.rs"]
mod rows;
#[path="owned_original_facts.rs"]
mod owned_original_facts;
pub(in super::super) use owned_original_facts::OwnedOriginalFacts;

pub(in super::super) struct BurnReader<'anchor,'facts> {
    reader:ManagedConnection,
    anchor:Anchor<'anchor>,
    original:OriginalFacts<'facts>,
}
pub(in super::super) struct ObservedReader<'anchor,'facts> {
    reader:ManagedConnection,
    anchor:Anchor<'anchor>,
    seal:Seal<'facts>,
}
// Visible type only for private capture-core linkage. Fields/constructor stay private.
pub(super) struct Seal<'a> {
    original:OriginalFacts<'a>,burn:[u8;16],burned_at:i64,
}
// Both variants retain actual objects in C; neither proves cross-process admission.
enum Anchor<'a> {
    Managed(&'a ManagedConnection),
    Original(&'a crate::schema::TestOriginalDatabaseAnchor),
}
impl Anchor<'_> {
    fn verify(&self)->Result<()> {
        match self {
            Self::Managed(c)=>c.verify_retained_identity(),
            Self::Original(a)=>a.verify(),
        }
    }
}
fn same_anchor(reader:&ManagedConnection,anchor:&Anchor<'_>)->Result<()> {
    match anchor {
        Anchor::Managed(c)=>{
            if !reader.same_database_identity(c)? {return Err(Error::InvalidQuery);} Ok(())
        },
        Anchor::Original(a)=>a.verify_reader(reader),
    }
}
impl<'anchor,'facts> BurnReader<'anchor,'facts> {
    // Anchor's original authenticity/custody remains an external prerequisite.
    // No caller-selected connection/mode, mutable handle, or test-writer shortcut.
    pub(in super::super) fn open(path:&Path,anchor:&'anchor ManagedConnection,
        original:OriginalFacts<'facts>)->Result<Self> {
        Self::open_anchored(path,Anchor::Managed(anchor),original)
    }
    pub(in super::super) fn open_with_original_anchor(path:&Path,
        anchor:&'anchor crate::schema::TestOriginalDatabaseAnchor,
        original:OriginalFacts<'facts>)->Result<Self> {
        Self::open_anchored(path,Anchor::Original(anchor),original)
    }
    fn open_anchored(path:&Path,anchor:Anchor<'anchor>,original:OriginalFacts<'facts>)->Result<Self> {
        original.validate()?;anchor.verify()?;
        if path==Path::new(":memory:") {return Err(Error::InvalidQuery);}
        let reader=reopen_managed_connection_validated(path,ConnectionMode::Reader,
            |c|rows::identity(c,&original))?;
        same_anchor(&reader,&anchor)?;
        Ok(Self {reader,anchor,original})
    }
    // Every result consumes this reader, including the first error; no retry API.
    pub(in super::super) fn observe(self)->Result<ObservedReader<'anchor,'facts>> {
        let Self {mut reader,anchor,original}=self;
        same_anchor(&reader,&anchor)?;
        let result=reader.with_connection_mut(|c|observe_connection(c,original));
        same_anchor(&reader,&anchor)?;
        Ok(ObservedReader {reader,anchor,seal:result?})
    }
}
impl ObservedReader<'_,'_> {
    pub(in super::super) fn capture_terminal(self,incoming:OriginalFacts<'_>)->Result<(i64,Snapshot)> {
        let Self {mut reader,anchor,seal}=self;
        if !seal.matches(&incoming) {return Err(Error::InvalidQuery);}
        same_anchor(&reader,&anchor)?;
        let f=&seal.original;
        let owned=f.ownership.expected(seal.burn,seal.burned_at);
        let result=reader.with_connection_mut(|c|capture_core::capture(c,Limits::fixture(),
            Some(&incoming.intent),Some(&incoming.terminal),Some(&owned),Some(&seal)));
        same_anchor(&reader,&anchor)?;
        let (time,snapshot)=result?;
        Ok((time.ok_or(Error::InvalidQuery)?,snapshot))
    }
}
impl Seal<'_> {
    fn matches(&self,incoming:&OriginalFacts<'_>)->bool {self.original==*incoming}
    pub(super) fn check_in_tx(&self,c:&Connection,i:&ReceiptIntent<'_>,
        t:&terminal::Expected<'_>,o:&ownership::Expected<'_>)->Result<()> {
        let f=&self.original;
        if i!=&f.intent || t!=&f.terminal ||
            o!=&f.ownership.expected(self.burn,self.burned_at) {
            return Err(Error::InvalidQuery);
        }
        rows::identity(c,f)?;
        rows::spent(c,f,self.burn,self.burned_at)
    }
}
fn read_fence(c:&Connection)->Result<()> {
    let fenced:i64=c.query_row("PRAGMA query_only",[],|r|r.get(0))?;
    if fenced!=1 || !c.is_autocommit() {return Err(Error::InvalidQuery);} Ok(())
}
// Raw primitive is private, used only by observe and synthetic child tests.
fn observe_connection<'a>(c:&mut Connection,original:OriginalFacts<'a>)->Result<Seal<'a>> {
    original.validate()?;read_fence(c)?;
    let tx=c.transaction()?;
    rows::identity(&tx,&original)?;
    let (burn,burned_at)=rows::read_spent(&tx,&original)?;
    rows::preterminal(&tx,&original)?;
    tx.commit()?;
    Ok(Seal {original,burn,burned_at})
}
#[cfg(test)]
#[path="burn_observer_tests.rs"]
mod tests;
