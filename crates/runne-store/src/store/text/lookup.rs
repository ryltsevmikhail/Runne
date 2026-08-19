use super::super::parse_helpers::*;
use super::super::text_receipt_helpers::*;
use super::super::*;

impl StoreTransaction {
    pub(super) fn lookup_text_generation_receipt_impl(
        &self,
        command_id: CommandId,
        idempotency_key: &runne_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<TextGenerationReceiptLookup, CommitError> {
        let connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let scope = IdempotencyScopeCodec
            .encode(idempotency_scope)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        lookup_text_receipt(
            &connection,
            command_id,
            idempotency_key,
            &scope,
            fingerprint,
        )
    }
}
