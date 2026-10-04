use crate::codec::{IdempotencyScopeCodec, TextGenerationReceiptCodec};
use runne_application::ports::{OperationTag, TextGenerationPhase};

/// Validate Rejected-v6 cancellation receipts at managed open without reopening the store.
/// Provider-backed legacy receipts use the existing low-level verifier; receipts with no
/// linked effects must prove the distinct NoAdmission witness.
pub(crate) fn validate_no_admission_cancellation_receipts(
    connection: &Connection,
) -> SqliteResult<()> {
    let candidates: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
        let mut statement = connection.prepare(
            "SELECT command_id,idempotency_scope_bytes,command_outcome FROM command_receipts",
        )?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        rows.collect::<SqliteResult<Vec<_>>>()?
    };
    for (command_id, scope_bytes, outcome) in candidates {
        let scope = IdempotencyScopeCodec
            .decode(&scope_bytes)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if scope.operation != OperationTag::GenerateConversationText {
            continue;
        }
        let receipt = TextGenerationReceiptCodec
            .decode(&outcome)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if receipt.phase != TextGenerationPhase::Rejected || receipt.taskrun_version != 6 {
            continue;
        }
        if crate::store::terminal_cancellation_receipt::requires_no_admission_proof(
            connection, &receipt,
        )? {
            let begin_command: Vec<u8> = connection
                .query_row(
                    "SELECT command_id FROM events WHERE aggregate_type=2 AND aggregate_id=?1 AND sequence=?2",
                    rusqlite::params![
                        receipt.conversation_id.as_bytes(),
                        i64::try_from(receipt.conversation_version.saturating_sub(1))
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ],
                    |row| row.get(0),
                )?;
            if begin_command != command_id
                || !crate::store::terminal_cancellation_receipt::validate_no_admission_receipt(
                    connection, &receipt,
                )?
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
        } else {
            crate::store::terminal_cancellation_receipt::validate_terminal_cancellation_receipt(
                connection, &receipt,
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        }
    }
    Ok(())
}
