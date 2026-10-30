//! Test-only fresh-R successful-terminal receipt observation; no native owner.
use super::{fixture::ExistingDatabase, lost_ack_request::Request};
use crate::{
    codec::{IdempotencyScopeCodec, StoreCodec},
    store::{LocalCommandAttemptState, StoreTransaction},
};
use runne_application::{
    commands::CommandOutcome,
    fingerprint::CommandFingerprint,
    ports::{AggregateScope, EventStore, LoadedStream, OperationTag, ReceiptLookup, RuntimeAuthorityId},
};
use runne_domain::{
    command::TerminalResult,
    id::TaskRunId,
    task_run::{TaskRun, TaskRunEvent},
};
use serde::Deserialize;
use std::sync::Arc;

// All references are borrowed from C's admitted packet. R never owns C's root.
// The controller must authenticate the packet and retain its original anchor.
pub(super) struct RecoveryInput<'a> {
    pub database: ExistingDatabase<'a>,
    pub original_request: &'a [u8],
    pub run_nonce: [u8; 16],
    pub controller_pid: u32,
    pub writer_pid: u32,
    pub expected_outcome: CommandOutcome,
}

// Returned only after Store/connection ownership has been dropped.
// Stream is the actual public load, suitable for C's baseline comparison.
pub(super) struct RecoveryObservation {
    pub controller_pid: u32,
    pub writer_pid: u32,
    pub recovery_pid: u32,
    pub outcome: CommandOutcome,
    pub stream: LoadedStream,
}

// Read only the binding fields of an already Request::decode-validated packet.
// Request remains the sole implementation of the public receipt lookup.
#[derive(Deserialize)]
struct Binding {
    scope: Vec<u8>,
    fingerprint: [u8; 32],
}

fn validate_pids(controller: u32, writer: u32, recovery: u32) -> Result<(), &'static str> {
    if controller == 0 || writer == 0 || recovery == 0
        || controller == writer || controller == recovery || writer == recovery
    {
        return Err("roles must have distinct nonzero PIDs");
    }
    Ok(())
}

pub(super) fn recover(input: RecoveryInput<'_>) -> Result<RecoveryObservation, &'static str> {
    let recovery_pid = std::process::id();
    // This rejects same-process invocation. Supplied PID numbers alone are not
    // proof of process provenance; C must bind them to collected child handles.
    validate_pids(input.controller_pid, input.writer_pid, recovery_pid)?;
    let (task, version) = match &input.expected_outcome {
        CommandOutcome::TaskRunCompleted { taskrun_id, new_version } if *new_version > 0 => {
            (*taskrun_id, *new_version)
        }
        _ => return Err("expected TaskRunCompleted with positive version"),
    };
    runne_domain::id::validate_uuid_v7_bytes(task.as_bytes())
        .map_err(|_| "expected task identity")?;
    let request = Request::decode(input.original_request, &input.run_nonce)?;
    let binding: Binding = serde_json::from_slice(input.original_request)
        .map_err(|_| "request binding encoding")?;
    let scope = IdempotencyScopeCodec.decode(&binding.scope).map_err(|_| "request scope")?;
    let authority = RuntimeAuthorityId(hex::encode(input.database.authority));
    if scope.runtime_authority_id != authority
        || scope.operation != OperationTag::Complete
        || !matches!(scope.aggregate_scope,
            AggregateScope::ExistingTaskRun { taskrun_id } if taskrun_id == task)
    {
        return Err("request does not bind expected terminal scope");
    }
    let fingerprint = CommandFingerprint::for_complete(&task, &TerminalResult::Success, version - 1)
        .map_err(|_| "expected terminal fingerprint")?;
    if fingerprint.as_bytes() != &binding.fingerprint {
        return Err("request does not bind Success at expected version");
    }
    let (path, writer, reader) = input.database.open().map_err(|_| "validated existing reopen")?;
    let path = path.to_str().ok_or("database path encoding")?;
    // This normal constructor calls apply_migrations internally. ExistingDatabase
    // first requires CURRENT_SCHEMA_VERSION; see CONTRACT for the limited no-op
    // migration-path justification. No ensure/epoch/node/native owner is invoked.
    let store = StoreTransaction::open_with_connections(
        path, writer, reader, authority.clone(),
        Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
    ).map_err(|_| "store startup gates")?;
    let observed = observe(&store, &request, &authority, task, version, &input.expected_outcome);
    // No Store clone escapes. Drop also occurs before returning observe errors.
    // ManagedConnection Drop has no fallible close acknowledgement exposed here.
    drop(store);
    let (outcome, stream) = observed?;
    Ok(RecoveryObservation {
        controller_pid: input.controller_pid,
        writer_pid: input.writer_pid,
        recovery_pid,
        outcome,
        stream,
    })
}

fn observe(
    store: &StoreTransaction,
    request: &Request,
    authority: &RuntimeAuthorityId,
    task: TaskRunId,
    version: u64,
    expected: &CommandOutcome,
) -> Result<(CommandOutcome, LoadedStream), &'static str> {
    let outcome = match request.lookup(store, authority).map_err(|_| "public receipt lookup")? {
        ReceiptLookup::Duplicate { stored_result } if &stored_result == expected => stored_result,
        ReceiptLookup::Duplicate { .. } => return Err("terminal receipt outcome mismatch"),
        ReceiptLookup::Miss => return Err("original terminal receipt missing"),
    };
    let stream = store.load_task_run(task).map_err(|_| "public task stream load")?;
    if stream.current_version != version {
        return Err("terminal stream version mismatch");
    }
    if !matches!(stream.events.last().map(|event| event.payload()),
        Some(TaskRunEvent::TaskRunCompleted { result: TerminalResult::Success }))
    {
        return Err("stream lacks final factual Success");
    }
    // Replay the actual full history. A TaskRunCompleted receipt alone carries
    // task/version, so both the completion fingerprint and actual event matter.
    TaskRun::replay(&stream.events).map_err(|_| "terminal stream replay")?;
    let capture = store.load_local_command_permission_capture(task)
        .map_err(|_| "terminal capture load")?.ok_or("terminal capture missing")?;
    if capture.state != LocalCommandAttemptState::Completed {
        return Err("local attempt is not Completed");
    }
    // Repeat public lookup after observations; never re-commit the terminal.
    if request.lookup(store, authority).map_err(|_| "repeat public lookup")?
        != (ReceiptLookup::Duplicate { stored_result: outcome.clone() })
    {
        return Err("terminal receipt changed during observation");
    }
    Ok((outcome, stream))
}
