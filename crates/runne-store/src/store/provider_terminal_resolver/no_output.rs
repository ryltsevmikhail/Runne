use super::*;
use crate::store::taskrun_submit_origin::{
    RemoteTerminalTaskRunApplicability, verify_remote_terminal_taskrun_source,
};
use runne_application::ports::{AggregateScope, OperationTag};
use runne_domain::conversation::GenerationFailureReason as Reason;
use runne_domain::id::{AttemptId, ConversationId, TaskRunId};

type Source = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    i64,
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    i64,
);

pub(super) fn resolve(
    store: &StoreTransaction,
    attempt_id: runne_provider::DispatchAttemptId,
) -> Result<
    Option<runne_runtime::provider_execution::RecoveredProviderNoOutputCommand>,
    ProviderTerminalConversationResolveError,
> {
    let invalid = || ProviderTerminalConversationResolveError::Conflict;
    let mut reader = store
        .inner
        .reader
        .lock()
        .map_err(|_| ProviderTerminalConversationResolveError::Unavailable)?;
    let tx = reader
        .transaction()
        .map_err(|_| ProviderTerminalConversationResolveError::Unavailable)?;
    let source: Option<Source> = tx
        .query_row(
            "SELECT s.taskrun_id,s.taskrun_attempt_id,s.conversation_id,
                    s.writer_owner_principal,s.terminal_status,s.publication_disposition,
                    s.expected_taskrun_version,s.settlement_state,s.published_output_digest,
                    EXISTS(SELECT 1 FROM provider_accounting_settlements f
                           WHERE f.dispatch_attempt_id=s.dispatch_attempt_id)
             FROM provider_remote_terminal_settlements s
             LEFT JOIN provider_terminal_outbox o USING(dispatch_attempt_id)
             LEFT JOIN provider_remote_terminal_applications a USING(dispatch_attempt_id)
             WHERE s.dispatch_attempt_id=?1 AND s.source_kind=2
               AND o.dispatch_attempt_id IS NULL AND a.dispatch_attempt_id IS NULL",
            [attempt_id.as_bytes().as_slice()],
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
                    row.get(9)?,
                ))
            },
        )
        .optional()
        .map_err(|_| invalid())?;
    let Some((
        taskrun_bytes,
        task_attempt_bytes,
        conversation_bytes,
        pinned_writer,
        status,
        publication,
        started_version,
        state,
        output_digest,
        accounting_present,
    )) = source
    else {
        return Ok(None);
    };
    if !matches!(state, 1 | 3)
        || (status == 1 && publication == 0 && output_digest.is_some() && accounting_present != 0)
    {
        return Ok(None);
    }
    let taskrun = TaskRunId::from_bytes(taskrun_bytes.try_into().map_err(|_| invalid())?);
    let task_attempt = AttemptId::from_bytes(task_attempt_bytes.try_into().map_err(|_| invalid())?);
    let conversation =
        ConversationId::from_bytes(conversation_bytes.try_into().map_err(|_| invalid())?);
    let verified = verify_remote_terminal_taskrun_source(
        &tx,
        attempt_id.as_bytes(),
        &store.runtime_authority_id,
    )
    .map_err(|_| invalid())?;
    if verified.taskrun_id != taskrun
        || verified.taskrun_attempt_id != task_attempt
        || verified.writer_owner_principal != pinned_writer
    {
        return Err(invalid());
    }
    let disposition = match verified.applicability {
        RemoteTerminalTaskRunApplicability::ActiveRunning { taskrun_version } => {
            if i64::try_from(taskrun_version).ok() != Some(started_version) {
                return Err(invalid());
            }
            if !verified.publication_allowed {
                return Ok(None);
            }
            let reason = match (status, publication) {
                (1, 1..=5) => Reason::ProviderOutputRejected,
                (1, 0) => Reason::ProviderAccountingUnknown,
                (2 | 3 | 5, _) => Reason::ProviderExecutionFailed,
                _ => return Err(invalid()),
            };
            runne_runtime::provider_execution::RecoveredProviderNoOutputDisposition::Failure(reason)
        }
        RemoteTerminalTaskRunApplicability::AcceptedCancellation {
            taskrun_version,
            cancellation_event_id,
            cancellation_command_id,
        } => {
            if i64::try_from(taskrun_version).ok() != started_version.checked_add(1) {
                return Err(invalid());
            }
            let terminal = match status {
                1 => runne_application::provider::ProviderRemoteTerminalDisposition::Completed,
                2 => runne_application::provider::ProviderRemoteTerminalDisposition::Failed,
                3 => runne_application::provider::ProviderRemoteTerminalDisposition::Incomplete,
                5 => runne_application::provider::ProviderRemoteTerminalDisposition::Cancelled,
                _ => return Err(invalid()),
            };
            let artifact: Vec<u8> = tx.query_row(
                "SELECT artifact_digest FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
                [attempt_id.as_bytes().as_slice()],
                |row| row.get(0),
            ).map_err(|_| invalid())?;
            let artifact = artifact.try_into().map_err(|_| invalid())?;
            let evidence =
                runne_application::ports::ProviderRemoteArtifactCancellationEvidence::new(
                    *attempt_id.as_bytes(),
                    artifact,
                    terminal,
                    *cancellation_command_id.as_bytes(),
                    cancellation_event_id,
                    taskrun_version,
                )
                .ok_or_else(invalid)?;
            runne_runtime::provider_execution::RecoveredProviderNoOutputDisposition::Cancellation(
                evidence,
            )
        }
        RemoteTerminalTaskRunApplicability::ExactUserSupersession { .. }
        | RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion { .. } => {
            return Ok(None);
        }
    };
    let stream = super::super::conversation::load_conversation_from_connection(&tx, conversation)
        .map_err(|_| ProviderTerminalConversationResolveError::Unavailable)?;
    let event = stream
        .events
        .iter()
        .find(|event| {
            matches!(
                event.payload(),
                ConversationEvent::UserMessageAppended { taskrun_id, attempt_id, .. }
                    if *taskrun_id == taskrun && *attempt_id == task_attempt
            )
        })
        .ok_or_else(invalid)?;
    let (message_id, text) = match event.payload() {
        ConversationEvent::UserMessageAppended {
            message_id, text, ..
        } => (*message_id, text.clone()),
        _ => return Err(invalid()),
    };
    let command_id = *event.command_id();
    let key = event.idempotency_key().clone();
    let expected_version = event.sequence().checked_sub(1).ok_or_else(invalid)?;
    let (scope_bytes, outcome): (Vec<u8>, Vec<u8>) = tx.query_row(
        "SELECT idempotency_scope_bytes,command_outcome FROM command_receipts WHERE command_id=?1 AND idempotency_key=?2",
        rusqlite::params![command_id.as_bytes(), key.as_str().as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(|_| invalid())?;
    let scope = IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| invalid())?;
    let started = TextGenerationReceiptCodec
        .decode(&outcome)
        .map_err(|_| invalid())?;
    if started.phase != TextGenerationPhase::Started
        || started.conversation_id != conversation
        || started.taskrun_id != taskrun
        || started.attempt_id != task_attempt
        || started.user_message_id != message_id
        || i64::try_from(started.taskrun_version).ok() != Some(started_version)
        || scope.operation != OperationTag::GenerateConversationText
        || scope.runtime_authority_id != store.runtime_authority_id
        || scope.aggregate_scope
            != (AggregateScope::ExistingConversation {
                conversation_id: conversation,
            })
        || scope.principal_id.0 != verified.original_principal
    {
        return Err(invalid());
    }
    command_proof::verify_fingerprint(
        &tx,
        command_id,
        &key,
        conversation,
        expected_version,
        &text,
    )?;
    let actor = event.actor().clone();
    tx.commit()
        .map_err(|_| ProviderTerminalConversationResolveError::Unavailable)?;
    Ok(Some(
        runne_runtime::provider_execution::RecoveredProviderNoOutputCommand {
            context: runne_application::ports::ApplicationCommandContext {
                command_id,
                idempotency_key: key,
                principal_id: scope.principal_id,
                actor,
            },
            original: BeginConversationTextInput {
                conversation_id: conversation,
                expected_version,
                text,
            },
            started,
            disposition,
        },
    ))
}
