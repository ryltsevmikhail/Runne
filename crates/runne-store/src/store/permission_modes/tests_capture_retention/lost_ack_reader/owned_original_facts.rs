//! Independently owned fact copies only; no authenticity or custody proof.
use super::{Context, OriginalFacts};
use super::super::{terminal, ReceiptIntent};
use runne_domain::id::EventLogLineageId;
use rusqlite::{Error, Result};

pub(in super::super::super) struct OwnedOriginalFacts {
    fixed: OriginalFacts<'static>,
    authority: String,
    principal: String,
    key: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    actor: Vec<u8>,
    claim_scope: Vec<u8>,
    claim_key: Vec<u8>,
    attempt_stdout: Vec<u8>,
    attempt_stderr: Vec<u8>,
}
fn bytes(value: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(value.len()).map_err(|_| Error::InvalidQuery)?;
    out.extend_from_slice(value);
    Ok(out)
}
fn text(value: &str) -> Result<String> {
    let mut out = String::new();
    out.try_reserve_exact(value.len()).map_err(|_| Error::InvalidQuery)?;
    out.push_str(value);
    Ok(out)
}
impl OwnedOriginalFacts {
    pub(in super::super::super) fn try_from_view(f: &OriginalFacts<'_>) -> Result<Self> {
        // Validate every allocation bound before allocating anything.
        if f.intent.authority.len() > 65535 || f.intent.authority.is_empty() {
            return Err(Error::InvalidQuery);
        }
        if f.intent.principal.len() > 65535 || f.intent.principal.is_empty() {
            return Err(Error::InvalidQuery);
        }
        if f.intent.key.len() > 256 || f.intent.key.is_empty() {
            return Err(Error::InvalidQuery);
        }
        if f.terminal.stdout.len() > 65536 {
            return Err(Error::InvalidQuery);
        }
        if f.terminal.stderr.len() > 65536 {
            return Err(Error::InvalidQuery);
        }
        if f.terminal.actor.len() > 256 || f.terminal.actor.is_empty() {
            return Err(Error::InvalidQuery);
        }
        if f.ownership.claim_scope.len() > 1048576 || f.ownership.claim_scope.is_empty() {
            return Err(Error::InvalidQuery);
        }
        if f.ownership.claim_key.len() > 256 || f.ownership.claim_key.is_empty() {
            return Err(Error::InvalidQuery);
        }
        if f.ownership.attempt_stdout.len() > 65536 {
            return Err(Error::InvalidQuery);
        }
        if f.ownership.attempt_stderr.len() > 65536 {
            return Err(Error::InvalidQuery);
        }
        f.validate()?;
        let t = &f.terminal;
        if f.intent.version == 0 || f.intent.version > i64::MAX as u64 ||
            t.global_position <= 0 || !matches!(t.sensitivity, 0 | 2) ||
            t.stdout_observed < t.stdout.len() as i64 ||
            t.stderr_observed < t.stderr.len() as i64 {
            return Err(Error::InvalidQuery);
        }
        Ok(Self {
            fixed: rebind(f, "", "", &[], &[], &[], &[], &[], &[], &[], &[]),
            authority: text(f.intent.authority)?,
            principal: text(f.intent.principal)?,
            key: bytes(f.intent.key)?,
            stdout: bytes(f.terminal.stdout)?,
            stderr: bytes(f.terminal.stderr)?,
            actor: bytes(f.terminal.actor)?,
            claim_scope: bytes(f.ownership.claim_scope)?,
            claim_key: bytes(f.ownership.claim_key)?,
            attempt_stdout: bytes(f.ownership.attempt_stdout)?,
            attempt_stderr: bytes(f.ownership.attempt_stderr)?,
        })
    }
    pub(in super::super::super) fn view(&self) -> OriginalFacts<'_> {
        rebind(&self.fixed,
            &self.authority, &self.principal, &self.key, &self.stdout, &self.stderr,
            &self.actor, &self.claim_scope, &self.claim_key, &self.attempt_stdout, &self.attempt_stderr)
    }
}
// Rebuilds borrows into the owner; fixed contains only empty static borrows.
fn rebind<'a>(f: &OriginalFacts<'_>,
    authority: &'a str,
    principal: &'a str,
    key: &'a [u8],
    stdout: &'a [u8],
    stderr: &'a [u8],
    actor: &'a [u8],
    claim_scope: &'a [u8],
    claim_key: &'a [u8],
    attempt_stdout: &'a [u8],
    attempt_stderr: &'a [u8],
) -> OriginalFacts<'a> {
    OriginalFacts {
        authority: f.authority,
        lineage: EventLogLineageId::from_bytes(*f.lineage.as_bytes()),
        intent: ReceiptIntent {
            command: f.intent.command,
            task: f.intent.task,
            authority: authority,
            principal: principal,
            key: key,
            fingerprint: f.intent.fingerprint,
            version: f.intent.version,
        },
        terminal: terminal::Expected {
            task: f.terminal.task,
            attempt: f.terminal.attempt,
            binding_digest: f.terminal.binding_digest,
            event: f.terminal.event,
            fence: f.terminal.fence,
            stdout: stdout,
            stderr: stderr,
            stdout_observed: f.terminal.stdout_observed,
            stderr_observed: f.terminal.stderr_observed,
            actor: actor,
            causation: f.terminal.causation,
            global_position: f.terminal.global_position,
            sensitivity: f.terminal.sensitivity,
        },
        ownership: Context {
            invocation: f.ownership.invocation,
            area: f.ownership.area,
            owner: f.ownership.owner,
            generation: f.ownership.generation,
            node: f.ownership.node,
            epoch: f.ownership.epoch,
            assignment_lease: f.ownership.assignment_lease,
            occupation_lease: f.ownership.occupation_lease,
            claim_command: f.ownership.claim_command,
            claim_scope: claim_scope,
            claim_key: claim_key,
            claim_fingerprint: f.ownership.claim_fingerprint,
            claim_version: f.ownership.claim_version,
            admitted: f.ownership.admitted,
            started: f.ownership.started,
            conversation: f.ownership.conversation,
            workspace: f.ownership.workspace,
            command_digest: f.ownership.command_digest,
            attempt_stdout: attempt_stdout,
            attempt_stderr: attempt_stderr,
        },
    }
}

#[cfg(test)]
#[path = "owned_original_facts_tests.rs"]
mod tests;
