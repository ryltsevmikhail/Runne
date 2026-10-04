use super::*;
use crate::store::taskrun_submit_origin::{
    RemoteTerminalTaskRunApplicability, verify_remote_terminal_taskrun_source,
};
use runne_application::provider::ProviderTerminalOutboxSource;
use runne_domain::task_run::TaskRunState;
use rusqlite::Connection;

#[path = "remote_artifact/closed_cancellation.rs"]
mod closed_cancellation;

type RemoteTerminalSettlementSourceRow = (
    i64,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

pub(super) fn resolve_closed_cancellation(
    tx: &rusqlite::Transaction<'_>,
    record: &ProviderTerminalOutboxRecord,
    store: &StoreTransaction,
    durable: &runne_application::ports::TextGenerationReceipt,
) -> Result<
    Option<closed_cancellation::RecoveredClosedCancellation>,
    ProviderTerminalConversationResolveError,
> {
    closed_cancellation::resolve(tx, record, store, durable)
}

pub(super) fn verify_source(
    tx: &Connection,
    record: &ProviderTerminalOutboxRecord,
    artifact_digest: [u8; 32],
    store: &StoreTransaction,
) -> Result<bool, ProviderTerminalConversationResolveError> {
    let verified = crate::store::taskrun_submit_origin::verify_remote_terminal_taskrun_source(
        tx,
        record.attempt_id.as_bytes(),
        &store.runtime_authority_id,
    )
    .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
    if verified.taskrun_id != record.taskrun_id
        || verified.taskrun_attempt_id != record.execution_attempt_id
        || verified.conversation_id != record.conversation_id
        || verified.original_principal != record.principal_id
        || !matches!(record.source, ProviderTerminalOutboxSource::RemoteArtifact { artifact_digest: digest } if digest == artifact_digest)
    {
        return Err(ProviderTerminalConversationResolveError::Conflict);
    }
    let source: RemoteTerminalSettlementSourceRow = tx
        .query_row(
            "SELECT source_kind,settlement_state,terminal_status,publication_disposition,
                    artifact_digest,settlement_digest,begin_command_id,generation_id,
                    begin_event_digest
             FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [record.attempt_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
    if source.0 != 2
        || !matches!(source.1, 2 | 4)
        || source.2 != 1
        || source.3 != 0
        || source.4.as_slice() != artifact_digest.as_slice()
        || source.5.as_slice() != record.settlement_digest.as_slice()
        || source.6.as_slice() != verified.begin_command_id.as_bytes()
        || source.7.as_slice() != verified.generation_id.as_slice()
        || source.8.as_slice() != verified.begin_event_digest.as_slice()
    {
        return Err(ProviderTerminalConversationResolveError::Conflict);
    }
    let current_or_cancelling = matches!(
        verified.current_taskrun_state,
        TaskRunState::Running | TaskRunState::Cancelling
    );
    Ok(!current_or_cancelling
        || !verified.current_generation_active
        || (!verified.publication_allowed
            && verified.current_taskrun_state == TaskRunState::Running))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_audit_only(
    tx: &rusqlite::Transaction<'_>,
    record: &ProviderTerminalOutboxRecord,
    store: &StoreTransaction,
    command_id: runne_domain::id::CommandId,
    idempotency_key: &runne_domain::id::IdempotencyKey,
    actor: &runne_domain::event::Actor,
    expected_version: u64,
    text: &runne_domain::message::MessageText,
    started: &runne_application::ports::TextGenerationReceipt,
) -> Result<Option<RecoveredProviderConversationCommand>, ProviderTerminalConversationResolveError>
{
    let ProviderTerminalOutboxSource::RemoteArtifact { artifact_digest } = record.source else {
        return Ok(None);
    };
    if !verify_source(tx, record, artifact_digest, store)? {
        return Ok(None);
    }
    if started.phase != TextGenerationPhase::Started {
        return Ok(None);
    }
    audit_only(
        record,
        command_id,
        idempotency_key,
        actor,
        expected_version,
        text,
        started,
    )
    .map(Some)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_accepted_cancellation(
    tx: &rusqlite::Transaction<'_>,
    record: &ProviderTerminalOutboxRecord,
    store: &StoreTransaction,
    command_id: runne_domain::id::CommandId,
    idempotency_key: &runne_domain::id::IdempotencyKey,
    actor: &runne_domain::event::Actor,
    expected_version: u64,
    text: &runne_domain::message::MessageText,
    started: &runne_application::ports::TextGenerationReceipt,
) -> Result<Option<RecoveredProviderConversationCommand>, ProviderTerminalConversationResolveError>
{
    let ProviderTerminalOutboxSource::RemoteArtifact { artifact_digest } = record.source else {
        return Ok(None);
    };
    if started.phase != TextGenerationPhase::Started {
        return Ok(None);
    }
    let verified = verify_remote_terminal_taskrun_source(
        tx,
        record.attempt_id.as_bytes(),
        &store.runtime_authority_id,
    )
    .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
    let RemoteTerminalTaskRunApplicability::AcceptedCancellation {
        taskrun_version,
        cancellation_event_id,
        cancellation_command_id,
    } = verified.applicability
    else {
        return Ok(None);
    };
    if !verified.current_generation_active
        || verified.taskrun_id != record.taskrun_id
        || verified.taskrun_attempt_id != record.execution_attempt_id
        || verified.conversation_id != record.conversation_id
        || verified.original_principal != record.principal_id
    {
        return Err(ProviderTerminalConversationResolveError::Conflict);
    }
    let (source_kind, settlement_state, terminal_status, stored_digest): (i64, i64, i64, Vec<u8>) =
        tx.query_row(
            "SELECT source_kind,settlement_state,terminal_status,artifact_digest
             FROM provider_remote_terminal_settlements
             WHERE dispatch_attempt_id=?1 AND taskrun_id=?2 AND taskrun_attempt_id=?3
               AND conversation_id=?4",
            rusqlite::params![
                record.attempt_id.as_bytes(),
                record.taskrun_id.as_bytes(),
                record.execution_attempt_id.as_bytes(),
                record.conversation_id.as_bytes(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
    let disposition = match terminal_status {
        1 => runne_application::provider::ProviderRemoteTerminalDisposition::Completed,
        2 => runne_application::provider::ProviderRemoteTerminalDisposition::Failed,
        3 => runne_application::provider::ProviderRemoteTerminalDisposition::Incomplete,
        5 => runne_application::provider::ProviderRemoteTerminalDisposition::Cancelled,
        _ => return Err(ProviderTerminalConversationResolveError::Conflict),
    };
    if source_kind != 2
        || !(1..=5).contains(&settlement_state)
        || stored_digest.as_slice() != artifact_digest.as_slice()
    {
        return Err(ProviderTerminalConversationResolveError::Conflict);
    }
    let evidence = runne_application::ports::ProviderRemoteArtifactCancellationEvidence::new(
        *record.attempt_id.as_bytes(),
        artifact_digest,
        disposition,
        *cancellation_command_id.as_bytes(),
        cancellation_event_id,
        taskrun_version,
    )
    .ok_or(ProviderTerminalConversationResolveError::Conflict)?;
    let mut recovered = audit_only(
        record,
        command_id,
        idempotency_key,
        actor,
        expected_version,
        text,
        started,
    )?;
    recovered.terminal_cancellation = Some(
        runne_runtime::provider_execution::RecoveredProviderTerminalCancellation::RemoteArtifact(
            evidence,
        ),
    );
    recovered.audit_only = false;
    Ok(Some(recovered))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn audit_only(
    record: &ProviderTerminalOutboxRecord,
    command_id: runne_domain::id::CommandId,
    idempotency_key: &runne_domain::id::IdempotencyKey,
    actor: &runne_domain::event::Actor,
    expected_version: u64,
    text: &runne_domain::message::MessageText,
    started: &runne_application::ports::TextGenerationReceipt,
) -> Result<RecoveredProviderConversationCommand, ProviderTerminalConversationResolveError> {
    Ok(RecoveredProviderConversationCommand {
        context: runne_application::ports::ApplicationCommandContext {
            command_id,
            idempotency_key: idempotency_key.clone(),
            principal_id: PrincipalId(record.principal_id.clone()),
            actor: actor.clone(),
        },
        original: BeginConversationTextInput {
            conversation_id: record.conversation_id,
            expected_version,
            text: text.clone(),
        },
        started: started.clone(),
        terminal_cancellation: None,
        audit_only: true,
    })
}
