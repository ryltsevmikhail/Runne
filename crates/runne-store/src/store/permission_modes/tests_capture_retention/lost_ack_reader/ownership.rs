//! Selected success continuity only. Plain inputs are forgeable, not native authority.
use super::{ReceiptIntent,terminal,ownership_rows as rows};
use rows::Cell::{Blob as B,Text as T,Integer as I};
use rusqlite::{Connection,Error,Result,params};
// Retain independently BEFORE terminal commit, including already committed burn
// ID/time and legacy attempt output. Never infer these from terminal/result rows.
#[derive(PartialEq,Eq)]
pub(crate) struct Expected<'a> {
    pub invocation:[u8;16],pub area:[u8;100],pub owner:[u8;16],pub generation:[u8;8],
    pub burn:[u8;16],pub burned_at:i64,pub node:[u8;16],pub epoch:i64,
    pub assignment_lease:i64,pub occupation_lease:i64,pub claim_command:[u8;16],
    pub claim_scope:&'a [u8],pub claim_key:&'a [u8],pub claim_fingerprint:[u8;32],
    pub claim_version:i64,pub admitted:[u8;16],pub started:[u8;16],
    pub conversation:[u8;16],pub workspace:[u8;16],pub command_digest:[u8;32],
    pub attempt_stdout:&'a [u8],pub attempt_stderr:&'a [u8],
}
pub(super) fn check(c:&Connection,i:&ReceiptIntent<'_>,t:&terminal::Expected<'_>,
    e:&Expected<'_>)->Result<()> {
    if t.task!=i.task || t.fence<=0 || e.burned_at<=0 || e.epoch<=0 ||
        e.assignment_lease<=0 || e.occupation_lease<=0 || e.claim_version<=0 ||
        e.claim_scope.is_empty() || e.claim_scope.len()>1048576 ||
        e.claim_key.is_empty() || e.claim_key.len()>256 ||
        e.attempt_stdout.len()>65536 || e.attempt_stderr.len()>65536 {
        return Err(Error::InvalidQuery);
    }
    // Nonzero constraints selected from DDL/claim lookup; not UUID provenance.
    for id in [t.task.as_slice(),t.attempt.as_slice(),e.invocation.as_slice(),
        e.owner.as_slice(),e.generation.as_slice(),e.burn.as_slice(),e.node.as_slice(),
        e.admitted.as_slice(),e.started.as_slice()] {
        if id.iter().all(|b|*b==0) {return Err(Error::InvalidQuery);}
    }
    let version=i64::try_from(i.version).map_err(|_|Error::InvalidQuery)?;
    // Claim emits admitted/started before completion; these are separate events.
    // Local guards are necessary consistency, NOT authenticated origin/history.
    if e.claim_version<2 || e.claim_version>=version || e.admitted==e.started ||
        e.admitted==t.event || e.started==t.event || e.claim_command==i.command {
        return Err(Error::InvalidQuery);
    }
    for name in ["x2_permission_spent","taskrun_terminal_settlement_receipts",
        "taskrun_assignment_occupations","taskrun_assignments","taskrun_claim_receipts",
        "taskrun_local_command_attempts"] {rows::table(c,name)?;}
    // OR reverse domains include same-byte TEXT aliases, then strictly type-check.
    rows::spent(c,params![t.task.as_slice(),t.attempt.as_slice(),e.invocation.as_slice(),
        e.burn.as_slice()],&[B(&t.task),B(&t.attempt),B(&t.binding_digest),B(&e.invocation),
        B(&e.area),B(&e.owner),B(&e.generation),B(&e.burn),I(e.burned_at)])?;
    rows::settlement(c,params![t.task.as_slice(),t.fence,t.event.as_slice()],
        &[B(&t.task),I(t.fence),B(&t.attempt),B(&e.node),I(e.epoch),B(&t.event),I(version)])?;
    rows::occupation(c,params![t.task.as_slice(),t.fence,t.attempt.as_slice(),t.event.as_slice()],
        &[B(&t.task),I(t.fence),B(&t.attempt),B(&e.node),I(e.epoch),I(e.occupation_lease),
        T(b"released"),T(b"absent"),B(&t.event)])?;
    rows::assignment(c,params![t.task.as_slice(),t.fence,t.attempt.as_slice(),
        e.claim_command.as_slice(),e.admitted.as_slice(),e.started.as_slice()],
        &[B(&t.task),B(&t.attempt),B(&e.node),I(e.epoch),I(t.fence),T(b"linux-executor-v1"),
        I(e.assignment_lease),B(&e.claim_command),B(&e.admitted),B(&e.started)])?;
    // Raw claim scope equality only: this does NOT validate the claim scope codec.
    rows::claim(c,params![t.task.as_slice(),t.fence,t.attempt.as_slice(),e.claim_command.as_slice(),
        e.claim_scope,e.claim_key],&[B(&e.claim_command),B(e.claim_scope),B(e.claim_key),
        B(&e.claim_fingerprint),B(&t.task),B(&t.attempt),B(&e.node),I(e.epoch),I(t.fence),
        I(e.assignment_lease),I(e.claim_version),B(&e.admitted),B(&e.started)])?;
    // terminal_prepare leaves legacy output untouched; updated_at is not predicted.
    // Occupation can be renewed; no equality with immutable lease or raw ms/us order.
    rows::attempt(c,params![t.task.as_slice(),t.attempt.as_slice()],
        &[B(&t.task),B(&e.conversation),B(&e.workspace),B(&t.attempt),B(&e.node),I(e.epoch),
        I(t.fence),B(&e.command_digest),B(&e.area),T(b"completed"),
        B(e.attempt_stdout),B(e.attempt_stderr),I(0)])
}
