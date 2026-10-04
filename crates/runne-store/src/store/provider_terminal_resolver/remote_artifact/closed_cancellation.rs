use super::super::*;
use crate::store::taskrun_submit_origin::{
    RemoteTerminalTaskRunApplicability, verify_remote_terminal_taskrun_source,
};
use runne_application::ports::{ProviderRemoteArtifactCancellationEvidence, TextGenerationPhase};
use runne_application::provider::ProviderRemoteTerminalDisposition;
use runne_domain::task_run::{TaskRunEvent, TaskRunState};
use rusqlite::OptionalExtension;

type RemoteArtifactCancellationClosureRow = (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, i64);

pub(crate) struct RecoveredClosedCancellation {
    pub(crate) started: runne_application::ports::TextGenerationReceipt,
    pub(crate) evidence: ProviderRemoteArtifactCancellationEvidence,
}

pub(super) fn resolve(
    tx: &rusqlite::Transaction<'_>,
    record: &ProviderTerminalOutboxRecord,
    store: &StoreTransaction,
    durable: &runne_application::ports::TextGenerationReceipt,
) -> Result<Option<RecoveredClosedCancellation>, ProviderTerminalConversationResolveError> {
    let runne_application::provider::ProviderTerminalOutboxSource::RemoteArtifact {
        artifact_digest,
    } = record.source
    else {
        return Ok(None);
    };
    if durable.phase != TextGenerationPhase::Rejected {
        return Ok(None);
    }
    let invalid = || ProviderTerminalConversationResolveError::Conflict;
    if !crate::schema::verify_v60_remote_artifact_cancel_closures(tx).map_err(|_| invalid())? {
        return Err(invalid());
    }
    let verified = verify_remote_terminal_taskrun_source(
        tx,
        record.attempt_id.as_bytes(),
        &store.runtime_authority_id,
    )
    .map_err(|_| invalid())?;
    if verified.taskrun_id != record.taskrun_id
        || verified.taskrun_attempt_id != record.execution_attempt_id
        || verified.conversation_id != record.conversation_id
        || !matches!(
            &verified.applicability,
            RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion {
                taskrun_state: TaskRunState::Cancelled,
                terminal_payload,
                ..
            } if matches!(terminal_payload.as_ref(), TaskRunEvent::CancellationCompleted)
        )
    {
        return Ok(None);
    }
    let closure: Option<RemoteArtifactCancellationClosureRow> = tx
        .query_row(
            "SELECT artifact_digest,terminal_status,cancellation_command_id,
                    cancellation_event_id,cancellation_taskrun_version,
                    taskrun_terminal_event_id,taskrun_terminal_version
             FROM provider_remote_artifact_cancel_closures
             WHERE dispatch_attempt_id=?1 AND taskrun_id=?2 AND taskrun_attempt_id=?3
               AND conversation_id=?4",
            rusqlite::params![
                record.attempt_id.as_bytes(),
                record.taskrun_id.as_bytes(),
                record.execution_attempt_id.as_bytes(),
                record.conversation_id.as_bytes(),
            ],
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
        .map_err(|_| invalid())?;
    let Some((artifact, status, command, event, cancel_version, terminal_event, terminal_version)) =
        closure
    else {
        return Ok(None);
    };
    let RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion {
        terminal_event_id,
        terminal_version: verified_terminal_version,
        ..
    } = verified.applicability
    else {
        return Err(invalid());
    };
    if artifact.as_slice() != artifact_digest.as_slice()
        || terminal_event.as_slice() != terminal_event_id.as_slice()
        || terminal_version != i64::try_from(verified_terminal_version).map_err(|_| invalid())?
        || terminal_version != i64::try_from(durable.taskrun_version).map_err(|_| invalid())?
        || !matches!(status, 1 | 2 | 3 | 5)
    {
        return Err(invalid());
    }
    let source_status: i64 = tx
        .query_row(
            "SELECT terminal_status FROM provider_remote_terminal_settlements
             WHERE dispatch_attempt_id=?1 AND taskrun_id=?2 AND taskrun_attempt_id=?3
               AND conversation_id=?4 AND source_kind=2 AND artifact_digest=?5
               AND terminal_status=?6 AND settlement_state BETWEEN 1 AND 5",
            rusqlite::params![
                record.attempt_id.as_bytes(),
                record.taskrun_id.as_bytes(),
                record.execution_attempt_id.as_bytes(),
                record.conversation_id.as_bytes(),
                artifact_digest.as_slice(),
                status,
            ],
            |row| row.get(0),
        )
        .map_err(|_| invalid())?;
    let disposition = match source_status {
        1 => ProviderRemoteTerminalDisposition::Completed,
        2 => ProviderRemoteTerminalDisposition::Failed,
        3 => ProviderRemoteTerminalDisposition::Incomplete,
        5 => ProviderRemoteTerminalDisposition::Cancelled,
        _ => return Err(invalid()),
    };
    let evidence = ProviderRemoteArtifactCancellationEvidence::new(
        *record.attempt_id.as_bytes(),
        artifact_digest,
        disposition,
        command.as_slice().try_into().map_err(|_| invalid())?,
        event.as_slice().try_into().map_err(|_| invalid())?,
        u64::try_from(cancel_version).map_err(|_| invalid())?,
    )
    .ok_or_else(invalid)?;
    let stream =
        crate::store::taskrun_claim::stream_validate::verify_stream(tx, record.taskrun_id, None)
            .map_err(|_| invalid())?;
    let mut start_versions = stream.events.iter().filter_map(|event| {
        matches!(
            event.payload(),
            TaskRunEvent::AttemptStarted { attempt_id }
                if *attempt_id == record.execution_attempt_id
        )
        .then_some(event.sequence())
    });
    let started_version = start_versions.next().ok_or_else(invalid)?;
    if start_versions.next().is_some() {
        return Err(invalid());
    }
    let mut started = durable.clone();
    started.phase = TextGenerationPhase::Started;
    started.conversation_version = durable
        .conversation_version
        .checked_sub(1)
        .ok_or_else(invalid)?;
    started.taskrun_version = started_version;
    Ok(Some(RecoveredClosedCancellation { started, evidence }))
}
