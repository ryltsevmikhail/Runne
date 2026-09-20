mod commit;
mod context_scope;
mod diagnose;
mod load;
mod receipts;

pub use diagnose::ConversationStreamHealth;

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
    ) -> Result<ConversationReceiptLookup, CommitError> {
        self.lookup_conversation_receipt_impl(
            command_id,
            idempotency_key,
            idempotency_scope,
            fingerprint,
        )
    }

    fn commit_conversation(
        &self,
        payload: ConversationCommit,
    ) -> Result<ConversationCommitResult, CommitError> {
        self.commit_conversation_impl(payload)
    }
}
