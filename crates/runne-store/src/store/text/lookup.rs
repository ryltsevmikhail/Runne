use super::super::parse_helpers::*;
use super::super::text_receipt_helpers::*;
use super::super::*;

impl StoreTransaction {
    pub(super) fn lookup_claimed_text_generation_receipt_impl(
        &self,
        command_id: CommandId,
        idempotency_key: &runne_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
        assignment: &TaskRunAssignmentIdentity,
        claim_version: u64,
    ) -> Result<TextGenerationReceiptLookup, CommitError> {
        let result = self.lookup_text_generation_receipt_impl(
            command_id,
            idempotency_key,
            idempotency_scope,
            fingerprint,
        )?;
        if let TextGenerationReceiptLookup::Duplicate { stored_result } = &result {
            if stored_result.taskrun_id != assignment.taskrun_id
                || stored_result.attempt_id != assignment.attempt_id
            {
                return Err(storage_failure(StorageFailureKind::IntegrityViolation));
            }
            let connection = self
                .inner
                .reader
                .lock()
                .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
            super::claimed_begin_validation::verify_immutable_claim_identity(
                &connection,
                assignment,
                claim_version,
            )?;
        }
        Ok(result)
    }

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
            &self.runtime_authority_id,
        )
    }
}
