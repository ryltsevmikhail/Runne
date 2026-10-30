use crate::codec::{StoreCodec, TextGenerationReceiptCodec};
use crate::store::parse_helpers::parse_command_id_for_commit;
use runne_application::ports::TextGenerationPhase;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest as _, Sha256};

/// A stream ACK alone can also mean cancellation without publication.
/// Only the exact canonical D2 completion proves assistant publication here.
pub(crate) fn stream_completion_published(
    connection: &Connection,
    dispatch: &[u8],
    receipt_digest: &[u8],
    output_digest: &[u8],
) -> rusqlite::Result<bool> {
    let linked: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT c.command_id,r.command_outcome FROM d2_tool_loop_completions c
         JOIN command_receipts r ON r.command_id=c.command_id
         JOIN provider_terminal_outbox o ON o.outbox_id=c.terminal_outbox_id
          AND o.dispatch_attempt_id=c.terminal_attempt_id
         WHERE c.terminal_attempt_id=?1 AND c.completed_receipt_digest=?2
          AND c.assistant_text_digest=?3 AND o.receipt_digest=?2
          AND o.plaintext_digest=?3 AND o.state=2 AND o.applied_at IS NOT NULL",
            params![dispatch, receipt_digest, output_digest],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((command, encoded)) = linked else {
        return Ok(false);
    };
    if Sha256::digest(&encoded).as_slice() != receipt_digest {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let receipt = TextGenerationReceiptCodec
        .decode(&encoded)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    if receipt.phase != TextGenerationPhase::Completed {
        return Ok(false);
    }
    let command =
        parse_command_id_for_commit(command).map_err(|_| rusqlite::Error::InvalidQuery)?;
    super::d2::validate_d2_completed_receipt(connection, command, &receipt)
        .map_err(|_| rusqlite::Error::InvalidQuery)
}
