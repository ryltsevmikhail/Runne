mod begin;
mod finish;
mod lookup;
mod reject;

use super::*;

impl ConversationTextRepository for StoreTransaction {
    fn lookup_text_generation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &gocode_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<TextGenerationReceiptLookup, CommitError> {
        self.lookup_text_generation_receipt_impl(
            command_id,
            idempotency_key,
            idempotency_scope,
            fingerprint,
        )
    }

    fn begin_text_generation(
        &self,
        payload: BeginTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.begin_text_generation_impl(payload)
    }

    fn finish_text_generation(
        &self,
        payload: FinishTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.finish_text_generation_impl(payload)
    }

    fn reject_text_generation(
        &self,
        payload: RejectTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_impl(payload)
    }
}
