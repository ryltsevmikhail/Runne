mod commit;
mod context_scope;
mod diagnose;
mod fingerprint_compat;
mod load;
mod receipts;

pub use diagnose::ConversationStreamHealth;
pub(crate) use load::load_conversation_from_connection;

pub(crate) fn has_no_active_generation_before_global_position(
    connection: &rusqlite::Connection,
    conversation_id: ConversationId,
    global_position: i64,
) -> Result<bool, EventStoreError> {
    if global_position <= 0 {
        return Ok(false);
    }
    let stream = load_conversation_from_connection(connection, conversation_id)?;
    let prefix_len: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM events WHERE aggregate_type=2 AND aggregate_id=?1
             AND global_position<?2",
            rusqlite::params![conversation_id.as_bytes(), global_position],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let prefix_len = usize::try_from(prefix_len).map_err(|_| EventStoreError::CorruptData)?;
    let Some(prefix) = stream.events.get(..prefix_len) else {
        return Err(EventStoreError::CorruptData);
    };
    let replay = runne_domain::conversation::Conversation::replay(prefix)
        .map_err(|_| EventStoreError::CorruptData)?;
    Ok(replay.active_generation().is_none())
}

use super::*;

impl ConversationRepository for StoreTransaction {
    fn load_conversation(
        &self,
        conversation_id: ConversationId,
    ) -> Result<ConversationLoadedStream, EventStoreError> {
        self.load_conversation_impl(conversation_id)
    }

    fn lookup_conversation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &runne_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
        context_scope: runne_domain::conversation::ConversationContextScope,
    ) -> Result<ConversationReceiptLookup, CommitError> {
        self.lookup_conversation_receipt_impl(
            command_id,
            idempotency_key,
            idempotency_scope,
            fingerprint,
            context_scope,
        )
    }

    fn commit_conversation(
        &self,
        payload: ConversationCommit,
    ) -> Result<ConversationCommitResult, CommitError> {
        self.commit_conversation_impl(payload)
    }
}
