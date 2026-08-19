mod commit;
mod lookup;

use super::*;

impl UnitOfWork for StoreTransaction {
    fn lookup_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &runne_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<ReceiptLookup, CommitError> {
        self.lookup_receipt_impl(command_id, idempotency_key, idempotency_scope, fingerprint)
    }

    fn commit(&self, payload: CommandCommit) -> Result<CommitResult, CommitError> {
        self.commit_impl(payload)
    }
}
