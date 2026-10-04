use super::taskrun_claim::stream_validate::verify_stream;
use super::*;
use runne_application::commands::BeginConversationTextInput;
use runne_application::ports::{RuntimeAuthorityId, TextGenerationReceipt};
use runne_domain::id::{CommandId, IdempotencyKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartedGenerationTaskRunState {
    Running,
    PendingCancellation,
}

/// Validates the exact TaskRun state associated with a durable Started text receipt.
/// The cancellation case is the sole legal one-event successor; it must remain pending.
pub(crate) fn classify_started_generation_taskrun(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    original: &BeginConversationTextInput,
    command_id: CommandId,
    idempotency_key: &IdempotencyKey,
    scope: &IdempotencyScope,
    authority: &RuntimeAuthorityId,
) -> Result<StartedGenerationTaskRunState, ()> {
    let verified = verify_stream(connection, receipt.taskrun_id, None).map_err(|_| ())?;
    if verified.active_attempt != Some(receipt.attempt_id) {
        return Err(());
    }
    let (origin_payload, origin_command, origin_key): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT payload,command_id,idempotency_key FROM events
             WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1",
            [receipt.taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| ())?;
    let origin = TaskRunEventCodec.decode(&origin_payload).map_err(|_| ())?;
    let conversation =
        super::conversation::load_conversation_from_connection(connection, receipt.conversation_id)
            .map_err(|_| ())?;
    let created_workspace = match conversation.events.first().map(|event| event.payload()) {
        Some(ConversationEvent::ConversationCreated { workspace_id }) => *workspace_id,
        _ => return Err(()),
    };
    let workspace_id = match origin {
        TaskRunEvent::TaskRunSubmitted { .. } => {
            let origin = super::taskrun_submit_origin::verify_submitted_v2_origin(
                connection,
                receipt.taskrun_id,
                authority,
            )
            .map_err(|_| ())?
            .ok_or(())?;
            if origin.conversation_id != receipt.conversation_id
                || origin.input.prompt() != original.text.as_str()
                || origin.principal_id != scope.principal_id
                || scope.runtime_authority_id != *authority
            {
                return Err(());
            }
            origin.workspace_id
        }
        TaskRunEvent::TaskRunCreated
            if origin_command.as_slice() == command_id.as_bytes()
                && origin_key == idempotency_key.as_str().as_bytes() =>
        {
            let runne_application::ports::AggregateScope::ExistingConversation { conversation_id } =
                scope.aggregate_scope
            else {
                return Err(());
            };
            if scope.operation != runne_application::ports::OperationTag::GenerateConversationText
                || conversation_id != receipt.conversation_id
            {
                return Err(());
            }
            crate::project_workspace::lineage::validate_text_taskrun_lineage(
                connection,
                receipt.taskrun_id,
                created_workspace,
                command_id,
                scope,
            )
            .map_err(|_| ())?;
            created_workspace
        }
        _ => return Err(()),
    };
    let message_index =
        usize::try_from(receipt.conversation_version.checked_sub(1).ok_or(())?).map_err(|_| ())?;
    let matches_original = matches!(
        conversation.events.get(message_index).map(|event| event.payload()),
        Some(ConversationEvent::UserMessageAppended {
            taskrun_id,
            attempt_id,
            text,
            ..
        }) if *taskrun_id == receipt.taskrun_id
            && *attempt_id == receipt.attempt_id
            && text == &original.text
    );
    if created_workspace != workspace_id
        || workspace_id != receipt.workspace_id
        || !matches_original
    {
        return Err(());
    }
    let start_version = i64::try_from(receipt.taskrun_version).map_err(|_| ())?;
    let started_payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events
             WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2",
            params![receipt.taskrun_id.as_bytes(), start_version],
            |row| row.get(0),
        )
        .map_err(|_| ())?;
    if TaskRunEventCodec.decode(&started_payload).map_err(|_| ())?
        != (TaskRunEvent::AttemptStarted {
            attempt_id: receipt.attempt_id,
        })
    {
        return Err(());
    }
    if verified.version == receipt.taskrun_version
        && verified.state == runne_domain::task_run::TaskRunState::Running
    {
        return Ok(StartedGenerationTaskRunState::Running);
    }
    if verified.version == receipt.taskrun_version.checked_add(1).ok_or(())?
        && verified.state == runne_domain::task_run::TaskRunState::Cancelling
    {
        let successor_version = start_version.checked_add(1).ok_or(())?;
        let successor_payload: Vec<u8> = connection
            .query_row(
                "SELECT payload FROM events
                 WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2",
                params![receipt.taskrun_id.as_bytes(), successor_version],
                |row| row.get(0),
            )
            .map_err(|_| ())?;
        if TaskRunEventCodec
            .decode(&successor_payload)
            .map_err(|_| ())?
            == TaskRunEvent::CancellationRequested
        {
            return Ok(StartedGenerationTaskRunState::PendingCancellation);
        }
    }
    Err(())
}
