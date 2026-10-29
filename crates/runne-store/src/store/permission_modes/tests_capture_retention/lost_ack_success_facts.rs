//! Preterminal fixture transcript adapter. SOURCE_ONLY / NOTRUN; no new authority.
use super::super::logical_reader::{self, ReceiptIntent, terminal};
use super::{Context, fixture::Fixture};
use crate::{
    codec::{IdempotencyScopeCodec, StoreCodec},
    schema::TestOriginalDatabaseAnchor,
};
use logical_reader::burn_observer::{self, BurnReader, ObservedReader, OriginalFacts};
use runne_application::{permission_modes::LocalCommandPermissionBindingV1, ports::*};
use runne_domain::{event::Sensitivity, id::ConversationId};
use runne_platform::{
    local_command_linux::PermissionTargetObservationV1, process_managed_area::LinuxManagedArea,
};
use rusqlite::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
// Private wire fields; deserialize only through decode's whole-message bound.
// Area uses Vec because serde's built-in array support stops at 32 elements.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Facts {
    format: u16,
    request: Vec<u8>,
    authority: [u8; 16],
    lineage: runne_domain::id::EventLogLineageId,
    runtime: String,
    principal: String,
    command: [u8; 16],
    task: [u8; 16],
    key: Vec<u8>,
    fingerprint: [u8; 32],
    version: u64,
    attempt: [u8; 16],
    binding: [u8; 32],
    event: [u8; 16],
    fence: i64,
    actor: Vec<u8>,
    causation: Option<[u8; 16]>,
    position: i64,
    sensitivity: i64,
    invocation: [u8; 16],
    area: Vec<u8>,
    owner: [u8; 16],
    generation: [u8; 8],
    node: [u8; 16],
    epoch: i64,
    lease: i64,
    claim_command: [u8; 16],
    claim_scope: Vec<u8>,
    claim_key: Vec<u8>,
    claim_fingerprint: [u8; 32],
    claim_version: i64,
    admitted: [u8; 16],
    started: [u8; 16],
    conversation: [u8; 16],
    workspace: [u8; 16],
    command_digest: [u8; 32],
}
const WIRE_LIMIT: usize = 65_536;
fn integer(n: u64) -> Result<i64> {
    i64::try_from(n).map_err(|_| Error::InvalidQuery)
}
impl Facts {
    // Call after release/drain and before publishing intent or allowing commit.
    // Claim request/receipt and conversation MUST come from the real creation calls,
    // never SELECTs of claim/assignment/occupation/attempt/terminal/result rows.
    #[expect(
        clippy::too_many_arguments,
        reason = "retain independent original fixture sources"
    )]
    pub(super) fn freeze(
        context: &Context,
        f: &Fixture,
        b: &LocalCommandPermissionBindingV1,
        capture_digest: [u8; 32],
        payload: &CommandCommit,
        area: &LinuxManagedArea,
        observation: &PermissionTargetObservationV1,
        claim: (TaskRunClaimRequest, TaskRunClaimReceipt),
        conversation: ConversationId,
    ) -> Result<Self> {
        let (q, r) = claim;
        let a = b.assignment();
        let [event] = payload.events.as_slice() else {
            return Err(Error::InvalidQuery);
        };
        let version = payload
            .expected_version
            .checked_add(1)
            .ok_or(Error::InvalidQuery)?;
        let lease_micros = r.lease_expires_at.as_unix_micros();
        if lease_micros <= 0
            || lease_micros % 1000 != 0
            || q.taskrun_id != a.taskrun_id
            || q.attempt_id != a.attempt_id
            || q.node_id != a.node_id
            || q.node_epoch != a.node_epoch
            || r.taskrun_id != a.taskrun_id
            || r.attempt_id != a.attempt_id
            || r.node_id != a.node_id
            || r.node_epoch != a.node_epoch
            || r.fence != a.fence
            || r.new_version != b.claim_stream_version()
            || q.expected_version.checked_add(2) != Some(r.new_version)
            || r.admitted_event_id != *q.admitted_event.event_id()
            || r.started_event_id != *q.started_event.event_id()
            || payload.expected_version != b.claim_stream_version()
            || payload.idempotency_scope.runtime_authority_id != f.scope.runtime_authority_id
            || payload.idempotency_scope.principal_id.0 != f.principal.as_str()
            || event.command_id() != &payload.command_id
            || event.idempotency_key() != &payload.idempotency_key
        {
            return Err(Error::InvalidQuery);
        }
        if !matches!(payload.command_result, runne_application::commands::CommandOutcome::TaskRunCompleted {
            taskrun_id, new_version
        } if taskrun_id == a.taskrun_id && new_version == version)
            || !matches!(
                event.payload(),
                runne_domain::task_run::TaskRunEvent::TaskRunCompleted {
                    result: runne_domain::command::TerminalResult::Success
                }
            )
        {
            return Err(Error::InvalidQuery);
        }
        // Predict allocation from the PREterminal counter, never a terminal event.
        // Parent must keep all other writers quiescent through the terminal cut.
        let position = f.store.inner.reader.lock().unwrap().query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let facts = Self {
            format: 1,
            request: serde_json::to_vec(&super::Request::of(payload, context.run))
                .map_err(|_| Error::InvalidQuery)?,
            authority: context.authority,
            lineage: context.lineage,
            runtime: f.scope.runtime_authority_id.0.clone(),
            principal: f.principal.as_str().into(),
            command: *payload.command_id.as_bytes(),
            task: *a.taskrun_id.as_bytes(),
            key: payload.idempotency_key.as_str().as_bytes().into(),
            fingerprint: *payload.command_fingerprint.as_bytes(),
            version,
            attempt: *a.attempt_id.as_bytes(),
            binding: capture_digest,
            event: *event.event_id().as_bytes(),
            fence: integer(a.fence.0)?,
            actor: event.actor().as_str().as_bytes().into(),
            causation: event.causation_id().map(|id| *id.as_bytes()),
            position,
            sensitivity: match event.sensitivity() {
                Sensitivity::Public => 0,
                Sensitivity::Sensitive => 2,
                Sensitivity::Internal => return Err(Error::InvalidQuery),
            },
            invocation: *b.invocation_id().as_bytes(),
            area: area.identity().to_bytes().to_vec(),
            owner: *observation.owner_id(),
            generation: observation.owner_generation().to_be_bytes(),
            node: uuid::Uuid::parse_str(&a.node_id.0)
                .map_err(|_| Error::InvalidQuery)?
                .into_bytes(),
            epoch: integer(a.node_epoch)?,
            lease: lease_micros / 1000,
            claim_command: *q.command_id.as_bytes(),
            claim_scope: IdempotencyScopeCodec
                .encode(&q.idempotency_scope)
                .map_err(|_| Error::InvalidQuery)?,
            claim_key: q.idempotency_key.as_str().as_bytes().into(),
            claim_fingerprint: *q.command_fingerprint.as_bytes(),
            claim_version: integer(r.new_version)?,
            admitted: *q.admitted_event.event_id().as_bytes(),
            started: *q.started_event.event_id().as_bytes(),
            conversation: *conversation.as_bytes(),
            workspace: *f.scope.workspace_id.as_bytes(),
            command_digest: b.command().intent_digest(),
        };
        facts.checked()?;
        Ok(facts)
    }
    fn view(&self) -> Result<OriginalFacts<'_>> {
        Ok(OriginalFacts {
            authority: self.authority,
            lineage: self.lineage,
            intent: ReceiptIntent {
                command: self.command,
                task: self.task,
                authority: &self.runtime,
                principal: &self.principal,
                key: &self.key,
                fingerprint: self.fingerprint,
                version: self.version,
            },
            terminal: terminal::Expected {
                task: self.task,
                attempt: self.attempt,
                binding_digest: self.binding,
                event: self.event,
                fence: self.fence,
                stdout: b"retry-out",
                stderr: b"retry-err",
                stdout_observed: 9,
                stderr_observed: 9,
                actor: &self.actor,
                causation: self.causation,
                global_position: self.position,
                sensitivity: self.sensitivity,
            },
            ownership: burn_observer::Context {
                invocation: self.invocation,
                area: self
                    .area
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidQuery)?,
                owner: self.owner,
                generation: self.generation,
                node: self.node,
                epoch: self.epoch,
                assignment_lease: self.lease,
                occupation_lease: self.lease,
                claim_command: self.claim_command,
                claim_scope: &self.claim_scope,
                claim_key: &self.claim_key,
                claim_fingerprint: self.claim_fingerprint,
                claim_version: self.claim_version,
                admitted: self.admitted,
                started: self.started,
                conversation: self.conversation,
                workspace: self.workspace,
                command_digest: self.command_digest,
                // Fresh fixture starts empty; native terminal path leaves legacy output untouched.
                attempt_stdout: b"",
                attempt_stderr: b"",
            },
        })
    }
    fn checked(&self) -> Result<()> {
        if self.format != 1
            || self.request.len() > 16_384
            || self.runtime != hex::encode(self.authority)
        {
            return Err(Error::InvalidQuery);
        }
        // Reuse the Reader's complete bounded-input validation, not a second oracle.
        burn_observer::OwnedOriginalFacts::try_from_view(&self.view()?)?;
        Ok(())
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        self.checked()?;
        let wire = serde_json::to_vec(self).map_err(|_| Error::InvalidQuery)?;
        if wire.len() > WIRE_LIMIT {
            return Err(Error::InvalidQuery);
        }
        Ok(wire)
    }
    pub(super) fn decode(wire: &[u8]) -> Result<Self> {
        if wire.len() > WIRE_LIMIT {
            return Err(Error::InvalidQuery);
        }
        let facts: Self = serde_json::from_slice(wire).map_err(|_| Error::InvalidQuery)?;
        facts.checked()?;
        Ok(facts)
    }
    pub(super) fn check_intent(&self, intent: &super::Intent) -> Result<()> {
        if self.request != intent.request
            || self.command != intent.command
            || self.task != intent.task
            || self.attempt != intent.attempt
            || self.fingerprint != intent.fingerprint
            || self.key != intent.key.as_bytes()
            || self.version != intent.version
            || self.area != intent.area
        {
            return Err(Error::InvalidQuery);
        }
        Ok(())
    }
    // C owns both this decoded object and the retained original mainDB anchor.
    // Complete observe BEFORE publishing commit-go; retain the returned reader.
    pub(super) fn observe<'anchor, 'facts>(
        &'facts self,
        path: &Path,
        anchor: &'anchor TestOriginalDatabaseAnchor,
    ) -> Result<ObservedReader<'anchor, 'facts>> {
        self.checked()?;
        BurnReader::open_with_original_anchor(path, anchor, self.view()?)?.observe()
    }
    // Invoke once after receipt visibility, before owner death. The seal rejects
    // changed incoming facts and the existing Reader checks all rows in one cut.
    pub(super) fn capture(
        &self,
        observed: ObservedReader<'_, '_>,
    ) -> Result<(i64, logical_reader::Snapshot)> {
        observed.capture_terminal(self.view()?)
    }
}
