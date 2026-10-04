struct UnknownBeginReceiptExpectation<'a> {
    conversation_id: ConversationId,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    message_id: runne_domain::id::MessageId,
    text: &'a runne_domain::message::MessageText,
    event: &'a runne_domain::event::EventEnvelope<runne_domain::conversation::ConversationEvent>,
    taskrun_version: u64,
    expected_principal: &'a str,
    workspace_id: runne_domain::id::WorkspaceId,
}

fn verify_unknown_begin_receipt(
    connection: &Connection,
    expected: UnknownBeginReceiptExpectation<'_>,
) -> Result<[u8; 32], ProviderExecutionError> {
    let UnknownBeginReceiptExpectation {
        conversation_id,
        taskrun_id,
        attempt_id,
        message_id,
        text,
        event,
        taskrun_version,
        expected_principal,
        workspace_id,
    } = expected;
    use crate::codec::StoreCodec;
    use runne_application::fingerprint::CommandFingerprint;
    use runne_application::ports::{AggregateScope, OperationTag, TextGenerationPhase};

    let command_id = *event.command_id();
    let (scope_bytes, key_bytes, fingerprint, outcome): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
        connection
            .query_row(
                "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome
                 FROM command_receipts WHERE command_id=?1",
                [command_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let scope = crate::codec::IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let receipt = crate::codec::TextGenerationReceiptCodec
        .decode(&outcome)
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let previous_version = event
        .sequence()
        .checked_sub(1)
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
    let expected = CommandFingerprint::for_generate_conversation_text(
        &conversation_id,
        previous_version,
        text,
    );
    if !matches!(
        &scope.aggregate_scope,
        AggregateScope::ExistingConversation { conversation_id: scoped }
            if *scoped == conversation_id
    ) {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let (authority_id, admitted_principal): (Vec<u8>, String) = connection.query_row(
        "SELECT runtime_authority_id,principal_id FROM provider_execution_admissions WHERE taskrun_id=?1 AND execution_attempt_id=?2",
        params![taskrun_id.as_bytes().as_slice(), attempt_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if key_bytes != event.idempotency_key().as_str().as_bytes()
        || fingerprint.as_slice() != expected.as_bytes()
        || scope.operation != OperationTag::GenerateConversationText
        || scope.runtime_authority_id.0 != compact_unknown_hex(&authority_id)
        || receipt.phase != TextGenerationPhase::Started
        || receipt.conversation_id != conversation_id
        || receipt.workspace_id != workspace_id
        || receipt.taskrun_id != taskrun_id
        || receipt.attempt_id != attempt_id
        || receipt.user_message_id != message_id
        || receipt.conversation_version != event.sequence()
        || receipt.taskrun_version != taskrun_version
        || scope.principal_id.0 != expected_principal
        || admitted_principal != expected_principal
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let mut digest = Sha256::new();
    digest.update(b"GOCODE_PROVIDER_UNKNOWN_BEGIN_RECEIPT_V1\0");
    for field in [
        command_id.as_bytes().as_slice(),
        scope_bytes.as_slice(),
        key_bytes.as_slice(),
        fingerprint.as_slice(),
        outcome.as_slice(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    Ok(digest.finalize().into())
}

fn compact_unknown_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}
