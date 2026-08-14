use gocode_api::{
    AuthoritativeCommandOutcome, AuthoritativeTextGenerationOutcome, CanonicalConversationMessage,
    CanonicalMessageRole, CommandReconciliationContext, ConversationCreatedAck,
};
use gocode_application::command_reconciliation::{
    CommandReconciliationEvidence as Evidence, CommandReconciliationRepositoryError as Error,
};
use gocode_application::ports::{IdempotencyScope, TextGenerationPhase, TextGenerationReceipt};
use gocode_domain::conversation::{ConversationEvent, GenerationFailureReason};
use gocode_domain::id::{AttemptId, ConversationId, MessageId, TaskRunId, WorkspaceId};
use gocode_domain::task_run::TaskRunEvent;
use rusqlite::{Transaction, params};

use crate::codec::{
    ConversationEventCodec, ConversationReceiptCodec, StoreCodec, TaskRunEventCodec,
    TextGenerationReceiptCodec,
};

pub(super) fn created(
    transaction: &Transaction<'_>,
    outcome: &[u8],
    conversation_id: ConversationId,
    workspace_id: WorkspaceId,
) -> Result<Evidence, Error> {
    let receipt = ConversationReceiptCodec
        .decode(outcome)
        .map_err(|_| Error::InvariantViolation)?;
    if receipt.conversation_id != conversation_id
        || receipt.workspace_id != workspace_id
        || receipt.new_version != 1
    {
        return Err(Error::InvariantViolation);
    }
    let payload: Vec<u8> = transaction.query_row("SELECT payload FROM events WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1", [conversation_id.as_bytes()], |row| row.get(0)).map_err(|_| Error::InvariantViolation)?;
    if !matches!(ConversationEventCodec.decode(&payload), Ok(ConversationEvent::ConversationCreated { workspace_id: stored }) if stored == workspace_id)
    {
        return Err(Error::InvariantViolation);
    }
    let committed_at = gocode_api::NonNegativeUnixMillis::new(
        receipt.committed_at.as_unix_micros().div_euclid(1_000),
    )
    .ok_or(Error::InvariantViolation)?;
    Ok(Evidence::Terminal(Box::new(
        AuthoritativeCommandOutcome::conversation_created(ConversationCreatedAck {
            conversation_id,
            workspace_id,
            stream_version: 1,
            committed_at,
        }),
    )))
}

pub(super) fn text_outcome(
    transaction: &Transaction<'_>,
    context: &CommandReconciliationContext,
    scope: &IdempotencyScope,
    outcome: &[u8],
    conversation_id: ConversationId,
    expected_version: u64,
) -> Result<Evidence, Error> {
    let receipt = TextGenerationReceiptCodec
        .decode(outcome)
        .map_err(|_| Error::InvariantViolation)?;
    let (expected_conversation, expected_taskrun) = match receipt.phase {
        TextGenerationPhase::Started => (expected_version.checked_add(1), Some(4)),
        _ => (expected_version.checked_add(2), Some(5)),
    };
    if receipt.conversation_id != conversation_id
        || expected_conversation != Some(receipt.conversation_version)
        || expected_taskrun != Some(receipt.taskrun_version)
    {
        return Err(Error::InvariantViolation);
    }
    if workspace(transaction, receipt.conversation_id)? != receipt.workspace_id {
        return Err(Error::InvariantViolation);
    }
    crate::project_workspace::lineage::validate_text_taskrun_lineage(
        transaction,
        receipt.taskrun_id,
        receipt.workspace_id,
        context.command_id(),
        scope,
    )
    .map_err(|_| Error::InvariantViolation)?;
    let user = message(
        transaction,
        &receipt,
        receipt.user_message_id,
        CanonicalMessageRole::User,
    )?;
    if receipt.phase == TextGenerationPhase::Started {
        return Ok(Evidence::TextGenerationStarted);
    }
    let terminal: Vec<u8> = transaction.query_row("SELECT payload FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1 AND sequence = ?2", params![receipt.taskrun_id.as_bytes(), receipt.taskrun_version as i64], |row| row.get(0)).map_err(|_| Error::InvariantViolation)?;
    match (
        receipt.phase,
        TaskRunEventCodec
            .decode(&terminal)
            .map_err(|_| Error::InvariantViolation)?,
    ) {
        (TextGenerationPhase::Completed, TaskRunEvent::TaskRunCompleted { .. }) => {
            completed(transaction, &receipt, conversation_id, user)
        }
        (
            phase @ (TextGenerationPhase::Rejected | TextGenerationPhase::ProhibitedInputRejected),
            TaskRunEvent::TaskRunFailed { .. },
        ) => rejected(transaction, &receipt, conversation_id, user, phase),
        _ => Err(Error::InvariantViolation),
    }
}

fn completed(
    transaction: &Transaction<'_>,
    receipt: &TextGenerationReceipt,
    conversation_id: ConversationId,
    user_message: CanonicalConversationMessage,
) -> Result<Evidence, Error> {
    let assistant = message(
        transaction,
        receipt,
        receipt.assistant_message_id,
        CanonicalMessageRole::Assistant,
    )?;
    Ok(Evidence::Terminal(Box::new(
        AuthoritativeCommandOutcome::conversation_text(
            AuthoritativeTextGenerationOutcome::Completed(gocode_api::ConversationTextResult {
                conversation_id,
                taskrun_id: receipt.taskrun_id,
                attempt_id: receipt.attempt_id,
                conversation_stream_version: receipt.conversation_version,
                taskrun_stream_version: receipt.taskrun_version,
                user_message,
                assistant_message: assistant,
            }),
        ),
    )))
}

fn rejected(
    transaction: &Transaction<'_>,
    receipt: &TextGenerationReceipt,
    conversation_id: ConversationId,
    user_message: CanonicalConversationMessage,
    phase: TextGenerationPhase,
) -> Result<Evidence, Error> {
    let reason = failure(transaction, receipt)?;
    let rejection = match phase {
        TextGenerationPhase::Rejected => AuthoritativeTextGenerationOutcome::Rejected {
            conversation_id,
            taskrun_id: receipt.taskrun_id,
            attempt_id: receipt.attempt_id,
            conversation_stream_version: receipt.conversation_version,
            taskrun_stream_version: receipt.taskrun_version,
            user_message,
            reserved_assistant_message_id: receipt.assistant_message_id,
            reason,
        },
        TextGenerationPhase::ProhibitedInputRejected => {
            AuthoritativeTextGenerationOutcome::ProhibitedInputRejected {
                conversation_id,
                taskrun_id: receipt.taskrun_id,
                attempt_id: receipt.attempt_id,
                conversation_stream_version: receipt.conversation_version,
                taskrun_stream_version: receipt.taskrun_version,
                user_message,
                reserved_assistant_message_id: receipt.assistant_message_id,
                reason,
            }
        }
        _ => return Err(Error::InvariantViolation),
    };
    Ok(Evidence::Terminal(Box::new(
        AuthoritativeCommandOutcome::conversation_text(rejection),
    )))
}

fn workspace(
    transaction: &Transaction<'_>,
    conversation_id: ConversationId,
) -> Result<WorkspaceId, Error> {
    let payload: Vec<u8> = transaction.query_row("SELECT payload FROM events WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1", [conversation_id.as_bytes()], |row| row.get(0)).map_err(|_| Error::InvariantViolation)?;
    match ConversationEventCodec
        .decode(&payload)
        .map_err(|_| Error::InvariantViolation)?
    {
        ConversationEvent::ConversationCreated { workspace_id } => Ok(workspace_id),
        _ => Err(Error::InvariantViolation),
    }
}

fn message(
    transaction: &Transaction<'_>,
    receipt: &TextGenerationReceipt,
    id: MessageId,
    role: CanonicalMessageRole,
) -> Result<CanonicalConversationMessage, Error> {
    let mut query = transaction.prepare("SELECT payload, timestamp FROM events WHERE aggregate_type = 2 AND aggregate_id = ?1 ORDER BY sequence").map_err(|_| Error::InvariantViolation)?;
    let rows = query
        .query_map([receipt.conversation_id.as_bytes()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|_| Error::InvariantViolation)?;
    for row in rows {
        let (payload, timestamp) = row.map_err(|_| Error::InvariantViolation)?;
        match ConversationEventCodec
            .decode(&payload)
            .map_err(|_| Error::InvariantViolation)?
        {
            ConversationEvent::UserMessageAppended {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } if role == CanonicalMessageRole::User
                && message_id == id
                && taskrun_id == receipt.taskrun_id
                && attempt_id == receipt.attempt_id =>
            {
                return canonical_message(
                    message_id,
                    role,
                    taskrun_id,
                    attempt_id,
                    text.as_str(),
                    timestamp,
                );
            }
            ConversationEvent::AssistantMessageAppended {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } if role == CanonicalMessageRole::Assistant
                && message_id == id
                && taskrun_id == receipt.taskrun_id
                && attempt_id == receipt.attempt_id =>
            {
                return canonical_message(
                    message_id,
                    role,
                    taskrun_id,
                    attempt_id,
                    text.as_str(),
                    timestamp,
                );
            }
            _ => {}
        }
    }
    Err(Error::InvariantViolation)
}

fn canonical_message(
    id: MessageId,
    role: CanonicalMessageRole,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    text: &str,
    timestamp: i64,
) -> Result<CanonicalConversationMessage, Error> {
    let committed_at = gocode_api::NonNegativeUnixMillis::new(timestamp.div_euclid(1_000))
        .ok_or(Error::InvariantViolation)?;
    Ok(CanonicalConversationMessage {
        message_id: id,
        role,
        taskrun_id,
        attempt_id,
        text: text.into(),
        committed_at,
    })
}

fn failure(
    transaction: &Transaction<'_>,
    receipt: &TextGenerationReceipt,
) -> Result<GenerationFailureReason, Error> {
    let payload: Vec<u8> = transaction.query_row("SELECT payload FROM events WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = ?2", params![receipt.conversation_id.as_bytes(), receipt.conversation_version as i64], |row| row.get(0)).map_err(|_| Error::InvariantViolation)?;
    match ConversationEventCodec
        .decode(&payload)
        .map_err(|_| Error::InvariantViolation)?
    {
        ConversationEvent::GenerationFailed {
            taskrun_id,
            attempt_id,
            reason,
        } if taskrun_id == receipt.taskrun_id && attempt_id == receipt.attempt_id => Ok(reason),
        _ => Err(Error::InvariantViolation),
    }
}
