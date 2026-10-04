use super::*;
use rusqlite::Connection;

/// Rechecks the canonical started-text TaskRun before a fresh provider effect.
/// The caller holds the same Immediate transaction used to create the effect.
pub(crate) fn verify_fresh_running_attempt(
    connection: &Connection,
    runtime_authority: [u8; 16],
    taskrun_id: TaskRunId,
    conversation_id: ConversationId,
    attempt_id: AttemptId,
    principal_id: &str,
) -> Result<(), ()> {
    let verified = taskrun_claim::stream_validate::verify_stream(connection, taskrun_id, None)
        .map_err(|_| ())?;
    if verified.state != TaskRunState::Running || verified.active_attempt != Some(attempt_id) {
        return Err(());
    }
    let start = verified.events.last().ok_or(())?;
    if start.payload() != &(TaskRunEvent::AttemptStarted { attempt_id }) {
        return Err(());
    }
    let conversation = conversation::load_conversation_from_connection(connection, conversation_id)
        .map_err(|_| ())?;
    let workspace_id = match conversation.events.first().map(|event| event.payload()) {
        Some(ConversationEvent::ConversationCreated { workspace_id }) => *workspace_id,
        _ => return Err(()),
    };
    let mut matching = conversation.events.iter().filter(|event| {
        matches!(event.payload(), ConversationEvent::UserMessageAppended {
            taskrun_id: owner, attempt_id: attempt, ..
        } if *owner == taskrun_id && *attempt == attempt_id)
    });
    let user = matching.next().ok_or(())?;
    if matching.next().is_some() {
        return Err(());
    }
    let ConversationEvent::UserMessageAppended {
        message_id, text, ..
    } = user.payload()
    else {
        return Err(());
    };
    let sequence = user.sequence();
    let previous_version = sequence.checked_sub(1).ok_or(())?;
    let command_id = *user.command_id();
    let key = user.idempotency_key().clone();
    let (scope_bytes, stored_key, fingerprint, outcome): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
        connection
            .query_row(
                "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome
                 FROM command_receipts WHERE command_id=?1",
                [command_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| ())?;
    let scope = IdempotencyScopeCodec.decode(&scope_bytes).map_err(|_| ())?;
    let receipt = TextGenerationReceiptCodec
        .decode(&outcome)
        .map_err(|_| ())?;
    let expected_fingerprint = CommandFingerprint::for_generate_conversation_text(
        &conversation_id,
        previous_version,
        text,
    );
    if stored_key != key.as_str().as_bytes()
        || fingerprint != expected_fingerprint.as_bytes()
        || scope.operation != OperationTag::GenerateConversationText
        || scope.aggregate_scope != (AggregateScope::ExistingConversation { conversation_id })
        || scope.principal_id.0 != principal_id
        || scope.runtime_authority_id.0 != compact_hex(&runtime_authority)
        || receipt.phase != TextGenerationPhase::Started
        || receipt.conversation_id != conversation_id
        || receipt.workspace_id != workspace_id
        || receipt.taskrun_id != taskrun_id
        || receipt.attempt_id != attempt_id
        || receipt.user_message_id != *message_id
        || receipt.conversation_version != sequence
        || receipt.taskrun_version != verified.version
    {
        return Err(());
    }
    let input = runne_application::commands::BeginConversationTextInput {
        conversation_id,
        expected_version: previous_version,
        text: text.clone(),
    };
    match taskrun_started_generation::classify_started_generation_taskrun(
        connection,
        &receipt,
        &input,
        command_id,
        &key,
        &scope,
        &RuntimeAuthorityId(compact_hex(&runtime_authority)),
    )
    .map_err(|_| ())?
    {
        taskrun_started_generation::StartedGenerationTaskRunState::Running => Ok(()),
        taskrun_started_generation::StartedGenerationTaskRunState::PendingCancellation => Err(()),
    }
}

/// Resolves and verifies the exact TaskRun attempt attached to a persisted admission.
pub(crate) fn verify_admitted_running_attempt(
    connection: &Connection,
    dispatch_attempt_id: &[u8; 16],
) -> Result<(), ()> {
    let (taskrun, conversation, attempt, authority, principal):
        (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String) =
        connection
            .query_row(
                "SELECT taskrun_id,conversation_id,execution_attempt_id,runtime_authority_id,principal_id
                 FROM provider_execution_admissions WHERE dispatch_attempt_id=?1",
                [dispatch_attempt_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .map_err(|_| ())?;
    verify_fresh_running_attempt(
        connection,
        authority.as_slice().try_into().map_err(|_| ())?,
        TaskRunId::from_bytes(taskrun.as_slice().try_into().map_err(|_| ())?),
        ConversationId::from_bytes(conversation.as_slice().try_into().map_err(|_| ())?),
        AttemptId::from_bytes(attempt.as_slice().try_into().map_err(|_| ())?),
        &principal,
    )
}

fn compact_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
