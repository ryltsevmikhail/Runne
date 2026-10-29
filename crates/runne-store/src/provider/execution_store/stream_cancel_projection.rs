use crate::codec::{StoreCodec as _, TextGenerationReceiptCodec};
use crate::store::taskrun_submit_origin::verify_remote_terminal_taskrun_source;
use runne_application::ports::{RuntimeAuthorityId, TextGenerationPhase};
use runne_application::provider::{ProviderExecutionError, ProviderRemoteAttemptRecord};
use runne_domain::task_run::TaskRunState;
use rusqlite::{OptionalExtension as _, Transaction, params};

/// This proves local cancellation after all bound coding rounds reached a safe
/// terminal/no-effect boundary. It never claims the provider was cancelled.
pub(super) fn proven(
    tx: &Transaction<'_>,
    record: &ProviderRemoteAttemptRecord,
) -> Result<bool, ProviderExecutionError> {
    let binding = &record.request.binding;
    if !matches!(
        binding.profile_id.as_str(),
        "runne-linux-agent-tools-v1" | "runne-deepseek-responses-tools/1"
    ) {
        return Ok(false);
    }
    let invalid = || ProviderExecutionError::JournalCorrupt;
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
    if verified.current_taskrun_state != TaskRunState::Cancelled {
        return Ok(false);
    }
    let Some(encoded) = tx
        .query_row(
            "SELECT command_outcome FROM command_receipts WHERE command_id=?1",
            [verified.begin_command_id.as_bytes()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|_| invalid())?
    else {
        return Ok(false);
    };
    let receipt = TextGenerationReceiptCodec
        .decode(&encoded)
        .map_err(|_| invalid())?;
    if receipt.phase != TextGenerationPhase::Rejected
        || receipt.taskrun_id != binding.taskrun_id
        || receipt.attempt_id != binding.taskrun_attempt_id
        || receipt.conversation_id != verified.conversation_id
        || receipt.taskrun_version != verified.current_taskrun_version
    {
        return Err(invalid());
    }
    let bound: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_provider_round_bindings b
         JOIN provider_execution_admissions a ON a.call_id=b.call_id
           AND a.taskrun_id=b.taskrun_id AND a.execution_attempt_id=b.attempt_id
         WHERE b.taskrun_id=?1 AND b.attempt_id=?2 AND a.dispatch_attempt_id=?3)",
            params![
                binding.taskrun_id.as_bytes(),
                binding.taskrun_attempt_id.as_bytes(),
                binding.dispatch_attempt_id.as_bytes()
            ],
            |r| r.get(0),
        )
        .map_err(|_| invalid())?;
    if !bound {
        return Err(invalid());
    }
    // This validator replays terminal task/conversation events, exact released
    // occupation, every invocation state and the entire provider-round chain.
    crate::store::terminal_cancellation_receipt::validate_terminal_cancellation_receipt(
        tx, &receipt,
    )
    .map_err(|_| invalid())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "explicit synthetic native PTY database only"]
    fn native_cancelled_rounds_prove_closed_without_remote_cancel_claim() {
        let path = std::env::var("RUNNE_SYNTHETIC_CANCELLATION_DB").unwrap();
        assert!(path.contains("/terminal-agent/pty-"));
        let mut connection =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let tx = connection.transaction().unwrap();
        let attempts: Vec<Vec<u8>> = tx
            .prepare("SELECT dispatch_attempt_id FROM provider_remote_request_intents")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let mut closures = 0;
        for attempt in attempts {
            let dispatch =
                runne_provider::DispatchAttemptId::from_bytes(attempt.try_into().unwrap());
            let record = super::super::read_remote_attempt_in_transaction(&tx, dispatch)
                .unwrap()
                .unwrap();
            if super::proven(&tx, &record).unwrap() {
                closures += 1;
                let mut wrong = record.clone();
                wrong.request.binding.taskrun_id =
                    runne_domain::id::TaskRunId::from_bytes([99; 16]);
                assert!(super::proven(&tx, &wrong).is_err());
            }
        }
        assert_eq!(closures, 1);
    }
}
