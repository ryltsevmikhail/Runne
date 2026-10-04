use super::super::parse_helpers::storage_failure;
use super::super::*;

pub(super) fn persist_claimed_text_receipt(
    tx: &rusqlite::Transaction<'_>,
    payload: &BeginClaimedTextGenerationCommit,
    scope: &[u8],
    now: i64,
) -> Result<(), CommitError> {
    let outcome = TextGenerationReceiptCodec
        .encode(&payload.receipt)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    tx.execute(
        "INSERT INTO command_receipts
         (command_id,idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome,committed_at)
         VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            payload.command_id.as_bytes(), scope,
            payload.idempotency_key.as_str().as_bytes(),
            payload.command_fingerprint.as_bytes(), outcome, now,
        ],
    ).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(())
}
