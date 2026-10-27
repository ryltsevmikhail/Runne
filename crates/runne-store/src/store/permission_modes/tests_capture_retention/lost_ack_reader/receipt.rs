//! Narrow pure receipt-byte oracle for a genuine-fixture caller. NOTRUN.
//! No SQL, cardinality/type proof, native evidence, trust, success-event proof,
//! timestamp crosslink, Reader or snapshot authority. No production codec calls.
//! Intent MUST be independently frozen before commit, never derived from Receipt.

pub(super) struct Intent<'a> {
    pub command: [u8;16],
    pub task: [u8;16],
    pub authority: &'a str,
    pub principal: &'a str,
    pub key: &'a [u8],
    pub fingerprint: [u8;32],
    pub version: u64,
}

// The SQL adapter must establish exact BLOB classes, INTEGER time and unique row.
// Borrowed slices avoid materializing untrusted fields here.
pub(super) struct Receipt<'a> {
    pub command: &'a [u8],
    pub scope: &'a [u8],
    pub key: &'a [u8],
    pub fingerprint: &'a [u8],
    pub outcome: &'a [u8],
    pub committed_at: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Refusal { Intent, Identity, Scope, Outcome, Time }

fn take(input: &mut &[u8], expected: &[u8]) -> bool {
    if !input.starts_with(expected) { return false; }
    *input = &input[expected.len()..];
    true
}
fn string(input: &mut &[u8], expected: &str) -> bool {
    let Ok(len) = u16::try_from(expected.len()) else { return false; };
    take(input,&len.to_be_bytes()) && take(input,expected.as_bytes())
}

// Hand checked against frozen v1 format: scope u16 version, two u16-length
// strings, Complete=5, ExistingTaskRun=1, task16; completed outcome version1,
// tag5, task16, u64BE version. Requires complete consumption of both inputs.
// CommandOutcome::TaskRunCompleted is NOT evidence of TerminalResult::Success.
pub(super) fn validate(i: &Intent<'_>, r: &Receipt<'_>) -> Result<(),Refusal> {
    if i.authority.is_empty() || i.authority.len()>u16::MAX as usize ||
        i.principal.is_empty() || i.principal.len()>u16::MAX as usize ||
        i.key.is_empty() || i.key.len()>256 || i.version==0 || i.version>i64::MAX as u64 {
        return Err(Refusal::Intent);
    }
    if r.command!=i.command.as_slice() || r.key!=i.key ||
        r.fingerprint!=i.fingerprint.as_slice() {
        return Err(Refusal::Identity);
    }
    let mut scope=r.scope;
    if !take(&mut scope,&[0,1]) || !string(&mut scope,i.authority) ||
        !string(&mut scope,i.principal) || !take(&mut scope,&[5,1]) ||
        !take(&mut scope,&i.task) || !scope.is_empty() {
        return Err(Refusal::Scope);
    }
    let mut outcome=r.outcome;
    if !take(&mut outcome,&[0,1,5]) || !take(&mut outcome,&i.task) ||
        !take(&mut outcome,&i.version.to_be_bytes()) || !outcome.is_empty() {
        return Err(Refusal::Outcome);
    }
    if r.committed_at<=0 { return Err(Refusal::Time); }
    Ok(())
}

#[cfg(test)]
#[path="receipt_tests.rs"]
mod tests;
