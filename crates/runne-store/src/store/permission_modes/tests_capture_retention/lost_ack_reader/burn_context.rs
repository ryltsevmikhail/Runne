//! Plain independently retained facts, not proof of original custody.
use super::super::{ownership,terminal,ReceiptIntent};
use runne_domain::id::{EventLogLineageId,validate_uuid_v7_bytes};
use rusqlite::{Error,Result};
#[derive(PartialEq,Eq)]
pub(in super::super::super) struct OriginalFacts<'a> {
    pub authority:[u8;16],pub lineage:EventLogLineageId,
    pub intent:ReceiptIntent<'a>,pub terminal:terminal::Expected<'a>,
    pub ownership:Context<'a>,
}
// This wrapper deliberately excludes burn/time: only the private SQL seal supplies them.
#[derive(PartialEq,Eq)]
pub(in super::super::super) struct Context<'a> {
    pub invocation:[u8;16],pub area:[u8;100],pub owner:[u8;16],pub generation:[u8;8],
    pub node:[u8;16],pub epoch:i64,pub assignment_lease:i64,pub occupation_lease:i64,
    pub claim_command:[u8;16],pub claim_scope:&'a [u8],pub claim_key:&'a [u8],
    pub claim_fingerprint:[u8;32],pub claim_version:i64,pub admitted:[u8;16],
    pub started:[u8;16],pub conversation:[u8;16],pub workspace:[u8;16],
    pub command_digest:[u8;32],pub attempt_stdout:&'a [u8],pub attempt_stderr:&'a [u8],
}
impl Context<'_> {
    pub(super) fn expected(&self,burn:[u8;16],burned_at:i64)->ownership::Expected<'_> {
        ownership::Expected {invocation:self.invocation,area:self.area,owner:self.owner,
            generation:self.generation,burn,burned_at,node:self.node,epoch:self.epoch,
            assignment_lease:self.assignment_lease,occupation_lease:self.occupation_lease,
            claim_command:self.claim_command,claim_scope:self.claim_scope,claim_key:self.claim_key,
            claim_fingerprint:self.claim_fingerprint,claim_version:self.claim_version,
            admitted:self.admitted,started:self.started,conversation:self.conversation,
            workspace:self.workspace,command_digest:self.command_digest,
            attempt_stdout:self.attempt_stdout,attempt_stderr:self.attempt_stderr}
    }
}
impl OriginalFacts<'_> {
    pub(super) fn validate(&self)->Result<()> {
        let t=&self.terminal;let o=&self.ownership;
        validate_uuid_v7_bytes(self.lineage.as_bytes()).map_err(|_|Error::InvalidQuery)?;
        for id in [self.authority.as_slice(),t.task.as_slice(),t.attempt.as_slice(),
            o.invocation.as_slice(),o.owner.as_slice(),o.generation.as_slice(),o.node.as_slice()] {
            if id.iter().all(|b|*b==0) {return Err(Error::InvalidQuery);}
        }
        let version=i64::try_from(self.intent.version).map_err(|_|Error::InvalidQuery)?;
        if t.task!=self.intent.task || t.fence<=0 || o.epoch<=0 ||
            o.assignment_lease<=0 || o.occupation_lease<=0 || o.claim_version<2 ||
            o.claim_version>=version || o.admitted==o.started || o.admitted==t.event ||
            o.started==t.event || o.claim_command==self.intent.command ||
            o.claim_scope.is_empty() || o.claim_scope.len()>1048576 ||
            o.claim_key.is_empty() || o.claim_key.len()>256 ||
            o.attempt_stdout.len()>65536 || o.attempt_stderr.len()>65536 {
            return Err(Error::InvalidQuery);
        }
        Ok(())
    }
}
