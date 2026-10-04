use super::*;
use crate::codec::{StoreCodec, TextGenerationReceiptCodec};
use sha2::{Digest, Sha256};

pub(super) fn matches(
    connection: &Connection,
    outbox_id: [u8; 16],
    attempt_id: [u8; 16],
    settlement_digest: [u8; 32],
    verified: &crate::store::taskrun_submit_origin::VerifiedRemoteTerminalTaskRunSource,
) -> rusqlite::Result<bool> {
    let outcome: Option<Vec<u8>> = connection
        .query_row(
            "SELECT command_outcome FROM command_receipts WHERE command_id=?1",
            [verified.begin_command_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(outcome) = outcome else {
        return Ok(false);
    };
    let Ok(receipt) = TextGenerationReceiptCodec.decode(&outcome) else {
        return Ok(false);
    };
    if receipt.conversation_id != verified.conversation_id
        || receipt.taskrun_id != verified.taskrun_id
        || receipt.attempt_id != verified.taskrun_attempt_id
    {
        return Ok(false);
    }
    let mut candidates = Vec::with_capacity(2);
    if matches!(
        receipt.phase,
        runne_application::ports::TextGenerationPhase::Started
            | runne_application::ports::TextGenerationPhase::Rejected
    ) {
        let mut hash = Sha256::new();
        hash.update(b"GOCODE_PROVIDER_REMOTE_ARTIFACT_AUDIT_ACK_V1\0");
        hash.update(outbox_id);
        hash.update(settlement_digest);
        hash.update(verified.taskrun_id.as_bytes());
        hash.update(verified.taskrun_attempt_id.as_bytes());
        let artifact_digest: Option<Vec<u8>> = connection
            .query_row(
                "SELECT artifact_digest FROM provider_remote_terminal_settlements
                 WHERE dispatch_attempt_id=?1 AND source_kind=2",
                [attempt_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(artifact_digest) = artifact_digest else {
            return Ok(false);
        };
        if artifact_digest.len() != 32 {
            return Ok(false);
        }
        hash.update(artifact_digest);
        candidates.push(hash.finalize().to_vec());
    }
    if matches!(
        receipt.phase,
        runne_application::ports::TextGenerationPhase::Completed
            | runne_application::ports::TextGenerationPhase::Rejected
    ) {
        let mut hash = Sha256::new();
        hash.update(b"GOCODE_PROVIDER_CONVERSATION_RECEIPT_V1\0");
        hash.update(outbox_id);
        hash.update(settlement_digest);
        hash.update(receipt.conversation_id.as_bytes());
        hash.update(receipt.taskrun_id.as_bytes());
        hash.update(receipt.attempt_id.as_bytes());
        hash.update(receipt.user_message_id.as_bytes());
        hash.update(receipt.assistant_message_id.as_bytes());
        hash.update(receipt.conversation_version.to_be_bytes());
        hash.update(receipt.taskrun_version.to_be_bytes());
        candidates.push(hash.finalize().to_vec());
    }
    for candidate in candidates {
        let Ok(receipt_digest) = <[u8; 32]>::try_from(candidate) else {
            return Ok(false);
        };
        if matches!(
            validate_remote_artifact_ack_inner(
                connection,
                outbox_id,
                attempt_id,
                settlement_digest,
                receipt_digest,
                2,
                false,
            ),
            Ok(Some(_))
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}
