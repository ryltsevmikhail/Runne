use crate::codec::{ConversationEventCodec, StoreCodec, TextGenerationReceiptCodec};
use crate::store::taskrun_submit_origin::{
    RemoteTerminalTaskRunApplicability, verify_remote_terminal_taskrun_source,
};
use runne_application::ports::{RuntimeAuthorityId, TextGenerationPhase, TextGenerationReceipt};
use runne_application::provider::{
    ProviderExecutionError, ProviderRemoteAttemptRecord, ProviderRemoteLocalDisposition as Local,
};
use runne_domain::{
    command::TerminalResult, conversation::ConversationEvent, task_run::TaskRunEvent,
};
use rusqlite::{OptionalExtension as _, Transaction, params};
use sha2::{Digest as _, Sha256};

type Ack = (Vec<u8>, Vec<u8>, Vec<u8>);

pub(super) fn classify(
    tx: &Transaction<'_>,
    record: &ProviderRemoteAttemptRecord,
    output: &[u8; 32],
) -> Result<Local, ProviderExecutionError> {
    let invalid = || ProviderExecutionError::JournalCorrupt;
    let binding = &record.request.binding;
    let ack: Option<Ack> = tx
        .query_row(
            "SELECT outbox_id,settlement_digest,receipt_digest FROM provider_terminal_outbox
         WHERE dispatch_attempt_id=?1 AND state=2 AND applied_at IS NOT NULL",
            [binding.dispatch_attempt_id.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|_| invalid())?;
    let Some((outbox, settlement, digest)) = ack else {
        return Ok(Local::Pending);
    };
    let authority = RuntimeAuthorityId(
        binding
            .runtime_authority_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    );
    let verified = verify_remote_terminal_taskrun_source(
        tx,
        binding.dispatch_attempt_id.as_bytes(),
        &authority,
    )
    .map_err(|_| invalid())?;
    let Some(encoded) = tx
        .query_row(
            "SELECT command_outcome FROM command_receipts WHERE command_id=?1",
            [verified.begin_command_id.as_bytes()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|_| invalid())?
    else {
        return Ok(Local::Unknown);
    };
    let receipt = TextGenerationReceiptCodec
        .decode(&encoded)
        .map_err(|_| invalid())?;
    if receipt.taskrun_id != verified.taskrun_id
        || receipt.attempt_id != verified.taskrun_attempt_id
        || receipt.conversation_id != verified.conversation_id
    {
        return Err(invalid());
    }
    let RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion {
        terminal_version,
        terminal_payload,
        ..
    } = verified.applicability
    else {
        return Ok(Local::Unknown);
    };
    if receipt.taskrun_version != terminal_version {
        return Err(invalid());
    }
    let legacy_digest = receipt_digest(&outbox, &settlement, &receipt);
    // D2 cancellation uses its canonical encoded receipt; legacy streams use V1.
    let d2 = matches!(
        binding.profile_id.as_str(),
        "runne-linux-agent-tools-v1" | "runne-deepseek-responses-tools/1"
    );
    let digest_matches =
        digest == legacy_digest || (d2 && Sha256::digest(&encoded).as_slice() == digest);
    if !digest_matches {
        return Ok(Local::Unknown);
    }
    if receipt.phase == TextGenerationPhase::Rejected
        && terminal_payload.as_ref() == &TaskRunEvent::CancellationCompleted
    {
        crate::store::terminal_cancellation_receipt::validate_terminal_cancellation_receipt(
            tx, &receipt,
        )
        .map_err(|_| invalid())?;
        return Ok(Local::AcceptedCancellationClosed);
    }
    if receipt.phase != TextGenerationPhase::Completed
        || d2
        || terminal_payload.as_ref()
            != &(TaskRunEvent::TaskRunCompleted {
                result: TerminalResult::Success,
            })
    {
        return Ok(Local::Unknown);
    }
    Ok(
        if assistant_matches(tx, verified.begin_command_id, &receipt, output)? {
            Local::OutputApplied
        } else {
            Local::Unknown
        },
    )
}

fn assistant_matches(
    tx: &Transaction<'_>,
    command_id: runne_domain::id::CommandId,
    receipt: &TextGenerationReceipt,
    output: &[u8; 32],
) -> Result<bool, ProviderExecutionError> {
    let invalid = || ProviderExecutionError::JournalCorrupt;
    let assistant: Option<(Vec<u8>,Vec<u8>)> = tx.query_row(
        "SELECT command_id,payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1 AND sequence=?2",
        params![receipt.conversation_id.as_bytes(), receipt.conversation_version],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional().map_err(|_| invalid())?;
    let Some((command, payload)) = assistant else {
        return Ok(false);
    };
    let event = ConversationEventCodec
        .decode(&payload)
        .map_err(|_| invalid())?;
    Ok(command == command_id.as_bytes()
        && matches!(event, ConversationEvent::AssistantMessageAppended {message_id,taskrun_id,attempt_id,text}
            if message_id==receipt.assistant_message_id && taskrun_id==receipt.taskrun_id
            && attempt_id==receipt.attempt_id && Sha256::digest(text.as_str().as_bytes()).as_slice()==output))
}

fn receipt_digest(outbox: &[u8], settlement: &[u8], receipt: &TextGenerationReceipt) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"GOCODE_PROVIDER_CONVERSATION_RECEIPT_V1\0");
    hash.update(outbox);
    hash.update(settlement);
    hash.update(receipt.conversation_id.as_bytes());
    hash.update(receipt.taskrun_id.as_bytes());
    hash.update(receipt.attempt_id.as_bytes());
    hash.update(receipt.user_message_id.as_bytes());
    hash.update(receipt.assistant_message_id.as_bytes());
    hash.update(receipt.conversation_version.to_be_bytes());
    hash.update(receipt.taskrun_version.to_be_bytes());
    hash.finalize().into()
}

#[cfg(test)]
#[path = "stream_text_projection_tests.rs"]
mod tests;
