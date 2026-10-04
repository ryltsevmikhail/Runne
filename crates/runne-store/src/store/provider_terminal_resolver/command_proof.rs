use super::*;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{AggregateScope, IdempotencyScope, OperationTag};
use runne_domain::id::{CommandId, IdempotencyKey};
use rusqlite::Connection;

pub(super) struct CommandProofExpectation<'a> {
    pub(super) record: &'a ProviderTerminalOutboxRecord,
    pub(super) scope: &'a IdempotencyScope,
    pub(super) command_id: CommandId,
    pub(super) key: &'a IdempotencyKey,
    pub(super) expected_version: u64,
    pub(super) text: &'a runne_domain::message::MessageText,
    pub(super) store: &'a StoreTransaction,
}

pub(super) fn verify(
    tx: &Connection,
    expected: CommandProofExpectation<'_>,
) -> Result<(), ProviderTerminalConversationResolveError> {
    let CommandProofExpectation {
        record,
        scope,
        command_id,
        key,
        expected_version,
        text,
        store,
    } = expected;
    if scope.runtime_authority_id != store.runtime_authority_id
        || scope.operation != OperationTag::GenerateConversationText
        || scope.aggregate_scope
            != (AggregateScope::ExistingConversation {
                conversation_id: record.conversation_id,
            })
        || scope.principal_id.0 != record.principal_id
    {
        return Err(ProviderTerminalConversationResolveError::Conflict);
    }
    let fingerprint: Vec<u8> = tx
        .query_row(
            "SELECT fingerprint FROM command_receipts
             WHERE command_id=?1 AND idempotency_key=?2",
            params![command_id.as_bytes(), key.as_str().as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
    let expected = CommandFingerprint::for_generate_conversation_text(
        &record.conversation_id,
        expected_version,
        text,
    );
    if fingerprint.as_slice() != expected.as_bytes() {
        return Err(ProviderTerminalConversationResolveError::Conflict);
    }
    Ok(())
}

pub(super) fn verify_fingerprint(
    tx: &Connection,
    command_id: CommandId,
    key: &IdempotencyKey,
    conversation_id: runne_domain::id::ConversationId,
    expected_version: u64,
    text: &runne_domain::message::MessageText,
) -> Result<(), ProviderTerminalConversationResolveError> {
    let fingerprint: Vec<u8> = tx
        .query_row(
            "SELECT fingerprint FROM command_receipts WHERE command_id=?1 AND idempotency_key=?2",
            params![command_id.as_bytes(), key.as_str().as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
    let expected = CommandFingerprint::for_generate_conversation_text(
        &conversation_id,
        expected_version,
        text,
    );
    if fingerprint.as_slice() != expected.as_bytes() {
        return Err(ProviderTerminalConversationResolveError::Conflict);
    }
    Ok(())
}
