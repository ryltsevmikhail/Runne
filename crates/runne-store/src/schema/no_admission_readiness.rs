use crate::codec::{IdempotencyScopeCodec, TextGenerationReceiptCodec};
use runne_application::ports::{OperationTag, TextGenerationPhase};
type Candidate = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Validate Rejected-v6 cancellation receipts at managed open without reopening the store.
/// Provider-backed legacy receipts use the existing low-level verifier; receipts with no
/// linked effects must prove the distinct NoAdmission witness.
pub(crate) fn validate_no_admission_cancellation_receipts(
    connection: &Connection,
) -> SqliteResult<()> {
    let candidates: Vec<Candidate> = {
        let mut statement = connection.prepare(
            "SELECT command_id,idempotency_scope_bytes,idempotency_key,command_outcome
             FROM command_receipts",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?;
        rows.collect::<SqliteResult<Vec<_>>>()?
    };
    for (command_id_bytes, scope_bytes, key_bytes, outcome) in candidates {
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
        let command_id = runne_domain::id::CommandId::from_bytes(
            command_id_bytes
                .as_slice()
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        );
        let idempotency_key = runne_domain::id::IdempotencyKey::new(
            String::from_utf8(key_bytes).map_err(|_| rusqlite::Error::InvalidQuery)?,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if crate::store::text_receipt_helpers::d2_failure::validate_d2_failed_receipt(
            connection,
            command_id,
            &idempotency_key,
            &scope,
            &receipt,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        {
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
            if begin_command != command_id.as_bytes()
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
