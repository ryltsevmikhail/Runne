use super::super::*;
use runne_application::commands::CommandOutcome;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    AggregateScope, OperationTag, RuntimeAuthorityId, StorageFailureKind,
};
use runne_domain::event::EventEnvelope;
use runne_domain::id::{AttemptId, CommandId, TaskRunId};
use runne_domain::task_run::{TaskRunEvent, TaskRunState};
use rusqlite::OptionalExtension;

type SuccessorReleaseReceiptRow = (Vec<u8>, Vec<u8>, i64, Vec<u8>, i64, String, Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RemoteTerminalTaskRunApplicability {
    ActiveRunning {
        taskrun_version: u64,
    },
    AcceptedCancellation {
        taskrun_version: u64,
        cancellation_event_id: [u8; 16],
        cancellation_command_id: CommandId,
    },
    ExactUserSupersession {
        taskrun_version: u64,
        successor_taskrun_id: TaskRunId,
        release_event_id: [u8; 16],
        release_version: u64,
    },
    AlreadyAppliedCompletion {
        taskrun_state: TaskRunState,
        terminal_event_id: [u8; 16],
        terminal_version: u64,
        terminal_payload: Box<TaskRunEvent>,
        release_reason: String,
    },
}

pub(super) struct RemoteTaskRunApplicabilityFacts<'a> {
    pub(super) taskrun_id: TaskRunId,
    pub(super) attempt_id: AttemptId,
    pub(super) version: u64,
    pub(super) state: TaskRunState,
    pub(super) active_attempt: Option<&'a AttemptId>,
    pub(super) events: &'a [EventEnvelope<TaskRunEvent>],
    pub(super) authority: &'a RuntimeAuthorityId,
    pub(super) origin: &'a super::VerifiedTaskRunSubmitOrigin,
}

pub(super) fn verify(
    connection: &Connection,
    facts: RemoteTaskRunApplicabilityFacts<'_>,
) -> Result<RemoteTerminalTaskRunApplicability, CommitError> {
    let RemoteTaskRunApplicabilityFacts {
        taskrun_id,
        attempt_id,
        version,
        state,
        active_attempt,
        events,
        authority,
        origin,
    } = facts;
    let invalid = || storage_failure(StorageFailureKind::IntegrityViolation);
    match state {
        TaskRunState::Running if active_attempt == Some(&attempt_id) => {
            Ok(RemoteTerminalTaskRunApplicability::ActiveRunning {
                taskrun_version: version,
            })
        }
        TaskRunState::Cancelling if active_attempt == Some(&attempt_id) => {
            accepted_cancellation(connection, taskrun_id, version, events, authority, origin)
        }
        TaskRunState::Unrecoverable => supersession(
            connection, taskrun_id, attempt_id, version, events, authority, origin,
        ),
        state if state.is_terminal() => {
            terminal_release(connection, taskrun_id, attempt_id, version, state, events)
        }
        _ => Err(invalid()),
    }
}

fn accepted_cancellation(
    connection: &Connection,
    taskrun_id: TaskRunId,
    version: u64,
    events: &[EventEnvelope<TaskRunEvent>],
    authority: &RuntimeAuthorityId,
    origin: &super::VerifiedTaskRunSubmitOrigin,
) -> Result<RemoteTerminalTaskRunApplicability, CommitError> {
    let invalid = || storage_failure(StorageFailureKind::IntegrityViolation);
    let event = events.last().ok_or_else(invalid)?;
    if event.sequence() != version || event.payload() != &TaskRunEvent::CancellationRequested {
        return Err(invalid());
    }
    let command_id = event.command_id();
    let (scope_bytes, key, fingerprint, outcome): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome
                 FROM command_receipts WHERE command_id=?1",
            [command_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| invalid())?;
    let scope = super::IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let expected_fingerprint =
        CommandFingerprint::for_cancel(&taskrun_id, version.checked_sub(1).ok_or_else(invalid)?);
    let outcome = super::CommandOutcomeCodec
        .decode(&outcome)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let valid_scope = scope.operation == OperationTag::CancelTaskRun
        && scope.runtime_authority_id == *authority
        && scope.aggregate_scope == (AggregateScope::ExistingTaskRun { taskrun_id });
    let valid_principal = scope.principal_id == origin.principal_id;
    let valid_actor = event.actor() == &origin.actor;
    let valid_key = event.idempotency_key().as_str().as_bytes() == key;
    let valid_fingerprint = fingerprint == expected_fingerprint.as_bytes();
    let valid_outcome = outcome
        == (CommandOutcome::TaskRunCancellationRequested {
            taskrun_id,
            new_version: version,
        });
    if !(valid_scope
        && valid_principal
        && valid_actor
        && valid_key
        && valid_fingerprint
        && valid_outcome)
    {
        return Err(invalid());
    }
    Ok(RemoteTerminalTaskRunApplicability::AcceptedCancellation {
        taskrun_version: version,
        cancellation_event_id: *event.event_id().as_bytes(),
        cancellation_command_id: *command_id,
    })
}

fn supersession(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    version: u64,
    events: &[EventEnvelope<TaskRunEvent>],
    authority: &RuntimeAuthorityId,
    origin: &super::VerifiedTaskRunSubmitOrigin,
) -> Result<RemoteTerminalTaskRunApplicability, CommitError> {
    let invalid = || storage_failure(StorageFailureKind::IntegrityViolation);
    let tail = events.last().ok_or_else(invalid)?;
    let TaskRunEvent::UserSupersedeUnknown {
        predecessor_attempt_id,
        successor_taskrun_id: payload_successor_id,
        acknowledgement_digest,
    } = tail.payload()
    else {
        return Err(invalid());
    };
    let receipt: Option<SuccessorReleaseReceiptRow> = connection
        .query_row(
            "SELECT successor_taskrun_id,predecessor_event_id,predecessor_event_version,
                    occupation_release_event_id,occupation_release_version,
                    occupation_release_reason,acknowledgement_digest
             FROM taskrun_unknown_successor_receipts WHERE predecessor_taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let Some((
        successor,
        predecessor_event,
        predecessor_version,
        release_event,
        release_version,
        reason,
        ack,
    )) = receipt
    else {
        return Err(invalid());
    };
    let successor_taskrun_id = TaskRunId::from_bytes(fixed(successor)?);
    let release_event_id = fixed(release_event)?;
    let verified_origin =
        super::verify_submitted_v2_origin(connection, successor_taskrun_id, authority)?
            .ok_or_else(invalid)?;
    if verified_origin.conversation_id != origin.conversation_id
        || verified_origin.workspace_id != origin.workspace_id
        || verified_origin.project_id != origin.project_id
        || verified_origin.principal_id != origin.principal_id
        || verified_origin.actor != origin.actor
        || *predecessor_attempt_id != attempt_id
        || *payload_successor_id != successor_taskrun_id
        || *acknowledgement_digest.as_bytes() != ack.as_slice()
        || predecessor_event.as_slice() != tail.event_id().as_bytes()
        || predecessor_version != i64::try_from(version).map_err(|_| invalid())?
        || release_event_id.as_slice() != tail.event_id().as_bytes()
        || release_version != i64::try_from(version).map_err(|_| invalid())?
        || reason != "user_supersession"
    {
        return Err(invalid());
    }
    Ok(RemoteTerminalTaskRunApplicability::ExactUserSupersession {
        taskrun_version: version,
        successor_taskrun_id,
        release_event_id,
        release_version: u64::try_from(release_version)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
    })
}

fn terminal_release(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    version: u64,
    state: TaskRunState,
    events: &[EventEnvelope<TaskRunEvent>],
) -> Result<RemoteTerminalTaskRunApplicability, CommitError> {
    let invalid = || storage_failure(StorageFailureKind::IntegrityViolation);
    let tail = events.last().ok_or_else(invalid)?;
    let release_reason: Option<String> = connection
        .query_row(
            "SELECT 'terminal_settlement' WHERE EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts r
                JOIN taskrun_assignment_occupations o ON o.taskrun_id=r.taskrun_id AND o.fence=r.fence
                 AND o.attempt_id=r.attempt_id AND o.node_id=r.node_id AND o.node_epoch=r.node_epoch
                 AND o.state='released'
                AND o.release_event_id=r.terminal_event_id
                WHERE r.taskrun_id=?1 AND r.attempt_id=?2 AND r.terminal_version=?3
                 AND r.terminal_event_id=?4)",
            rusqlite::params![
                taskrun_id.as_bytes(),
                attempt_id.as_bytes(),
                i64::try_from(version).map_err(|_| invalid())?,
                tail.event_id().as_bytes(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let Some(release_reason) = release_reason else {
        return Err(invalid());
    };
    if tail.sequence() != version || !state.is_terminal() {
        return Err(invalid());
    }
    Ok(
        RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion {
            taskrun_state: state,
            terminal_event_id: *tail.event_id().as_bytes(),
            terminal_version: version,
            terminal_payload: Box::new(tail.payload().clone()),
            release_reason,
        },
    )
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], CommitError> {
    bytes
        .try_into()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}
