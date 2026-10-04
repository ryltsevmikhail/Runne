use super::super::parse_helpers::storage_failure;
use super::*;
use crate::store::taskrun_submit_origin::RemoteTerminalTaskRunApplicability;
use rusqlite::OptionalExtension;
use sha2::Digest as _;

type RemoteArtifactFinishAccountingRow = (
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

type Source = (
    Vec<u8>,
    Vec<u8>,
    String,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

pub(super) fn validate(
    tx: &rusqlite::Transaction<'_>,
    started: &TextGenerationReceipt,
    payload: &FinishTextGenerationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    let source: Option<Source> = tx
        .query_row(
            "SELECT dispatch_attempt_id,conversation_id,writer_owner_principal,
                writer_fencing_token,begin_command_id,generation_id,begin_event_digest,
                source_kind,terminal_status,publication_disposition,artifact_digest,
                profile_digest,pricing_revision_digest,expected_taskrun_version,
                settlement_state,input_tokens,output_tokens,cached_input_tokens,
                reasoning_output_tokens,charge_micros,currency,settlement_digest,
                published_output_digest
         FROM provider_remote_terminal_settlements
         WHERE taskrun_id=?1 AND taskrun_attempt_id=?2",
            rusqlite::params![started.taskrun_id.as_bytes(), started.attempt_id.as_bytes()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                    row.get(19)?,
                    row.get(20)?,
                    row.get(21)?,
                    row.get(22)?,
                ))
            },
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let Some(source) = source else {
        let remote_artifact_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_remote_request_intents q
             JOIN provider_remote_terminal_artifacts a USING(dispatch_attempt_id)
             WHERE q.taskrun_id=?1 AND q.taskrun_attempt_id=?2)",
                rusqlite::params![started.taskrun_id.as_bytes(), started.attempt_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        return if remote_artifact_exists {
            Err(storage_failure(StorageFailureKind::IntegrityViolation))
        } else {
            Ok(())
        };
    };
    if source.7 != 2
        || source.8 != 1
        || source.9 != 0
        || source.14 != 2
        || source.1.as_slice() != started.conversation_id.as_bytes()
        || source.13
            != i64::try_from(payload.expected_taskrun_version)
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?
        || payload.receipt.taskrun_id != started.taskrun_id
        || payload.receipt.attempt_id != started.attempt_id
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let dispatch = <[u8; 16]>::try_from(source.0.as_slice())
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let verified = crate::store::taskrun_submit_origin::verify_remote_terminal_taskrun_source(
        tx, &dispatch, authority,
    )
    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let exact_running = matches!(
        &verified.applicability,
        RemoteTerminalTaskRunApplicability::ActiveRunning { taskrun_version }
            if *taskrun_version == payload.expected_taskrun_version
    );
    if !exact_running
        || !verified.publication_allowed
        || verified.taskrun_id != started.taskrun_id
        || verified.taskrun_attempt_id != started.attempt_id
        || verified.conversation_id != started.conversation_id
        || verified.begin_command_id.as_bytes() != source.4.as_slice()
        || verified.generation_id.as_slice() != source.5.as_slice()
        || verified.begin_event_digest.as_slice() != source.6.as_slice()
        || verified.writer_owner_principal != source.2
        || i64::try_from(verified.writer_fencing_token).ok() != Some(source.3)
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    verify_source_artifact_accounting(tx, &source, dispatch)?;
    verify_published_output(&source, started, payload)?;
    Ok(())
}

fn verify_published_output(
    source: &Source,
    started: &TextGenerationReceipt,
    payload: &FinishTextGenerationCommit,
) -> Result<(), CommitError> {
    let expected = source
        .22
        .as_deref()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
    let [event] = payload.conversation_events.as_slice() else {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    };
    let runne_domain::conversation::ConversationEvent::AssistantMessageAppended {
        taskrun_id,
        attempt_id,
        text,
        ..
    } = event.payload()
    else {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    };
    let [taskrun_event] = payload.taskrun_events.as_slice() else {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    };
    if !matches!(
        taskrun_event.payload(),
        runne_domain::task_run::TaskRunEvent::TaskRunCompleted { .. }
    ) {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if *taskrun_id != started.taskrun_id || *attempt_id != started.attempt_id {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let actual: [u8; 32] = sha2::Sha256::digest(text.as_str().as_bytes()).into();
    if expected != Some(actual) {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

fn verify_source_artifact_accounting(
    tx: &rusqlite::Transaction<'_>,
    source: &Source,
    dispatch: [u8; 16],
) -> Result<(), CommitError> {
    let row: Option<RemoteArtifactFinishAccountingRow> = tx.query_row(
        "SELECT o.terminal_sequence,o.plaintext_digest,o.settlement_digest,a.pricing_revision_digest,
                a.settlement_digest,a.input_tokens,a.output_tokens,a.cached_input_tokens,
                a.reasoning_output_tokens,a.charge_micros,a.currency
         FROM provider_terminal_outbox o JOIN provider_accounting_settlements a
           ON a.dispatch_attempt_id=o.dispatch_attempt_id
         WHERE o.dispatch_attempt_id=?1 AND o.state=1",
        [dispatch.as_slice()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,
            row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?)),
    ).optional().map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let Some(row) = row else {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    };
    if row.0 != 0
        || row.1.as_slice() != source.10.as_slice()
        || row.2.as_slice() != source.21.as_deref().unwrap_or_default()
        || row.3.as_slice() != source.12.as_slice()
        || row.4.as_slice() != source.21.as_deref().unwrap_or_default()
        || (row.5, row.6, row.7, row.8, row.9, row.10.as_deref())
            != (
                source.15,
                source.16,
                source.17,
                source.18,
                source.19,
                source.20.as_deref(),
            )
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}
