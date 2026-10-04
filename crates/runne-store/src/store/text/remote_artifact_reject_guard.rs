use super::super::parse_helpers::storage_failure;
use super::*;
use crate::store::taskrun_submit_origin::RemoteTerminalTaskRunApplicability;
use rusqlite::OptionalExtension;

include!("remote_artifact_reject_guard_rows.rs");

pub(super) fn validate_non_output_rejection(
    tx: &rusqlite::Transaction<'_>,
    started: &TextGenerationReceipt,
    payload: &RejectTextGenerationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    use runne_domain::conversation::GenerationFailureReason as Reason;

    let source: Option<RemoteArtifactRejectSourceRow> = tx
        .query_row(
            "SELECT s.dispatch_attempt_id,s.source_kind,s.terminal_status,
                s.publication_disposition,s.conversation_id,s.begin_command_id,
                s.settlement_state,s.expected_taskrun_version,a.disposition,
                s.writer_owner_principal
             FROM provider_remote_terminal_settlements s
             JOIN provider_remote_terminal_artifacts a USING(dispatch_attempt_id)
             JOIN provider_remote_request_intents q USING(dispatch_attempt_id)
             WHERE s.taskrun_id=?1 AND s.taskrun_attempt_id=?2
               AND a.taskrun_id=s.taskrun_id AND a.taskrun_attempt_id=s.taskrun_attempt_id
               AND a.disposition=s.terminal_status
               AND a.request_digest=s.request_digest
               AND a.plaintext_digest=s.artifact_digest
               AND a.response_id_digest=s.response_id_digest
               AND a.profile_digest=s.profile_digest
               AND a.pricing_revision_digest=s.pricing_revision_digest
               AND a.runtime_authority_id=s.runtime_authority_id
               AND a.database_generation=s.database_generation
               AND a.runtime_generation=s.runtime_generation
               AND a.fencing_token=s.fencing_token
               AND q.taskrun_id=s.taskrun_id AND q.taskrun_attempt_id=s.taskrun_attempt_id
               AND q.request_digest=s.request_digest",
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
                ))
            },
        )
        .optional()
        .map_err(|_| {
            crate::store::test_support_diagnostics::record("reject.remote_source_query");
            storage_failure(StorageFailureKind::IntegrityViolation)
        })?;
    let Some((
        dispatch,
        source_kind,
        status,
        publication,
        conversation,
        command,
        settlement_state,
        expected_taskrun_version,
        artifact_status,
        pinned_writer,
    )) = source
    else {
        let remote_artifact_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_remote_request_intents q
                 LEFT JOIN provider_remote_terminal_artifacts a USING(dispatch_attempt_id)
                 LEFT JOIN provider_remote_terminal_settlements s USING(dispatch_attempt_id)
                 WHERE q.taskrun_id=?1 AND q.taskrun_attempt_id=?2
                   AND (a.dispatch_attempt_id IS NOT NULL OR s.dispatch_attempt_id IS NOT NULL))",
                rusqlite::params![started.taskrun_id.as_bytes(), started.attempt_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| {
                crate::store::test_support_diagnostics::record("reject.remote_orphan_query");
                storage_failure(StorageFailureKind::IntegrityViolation)
            })?;
        return if remote_artifact_exists {
            crate::store::test_support_diagnostics::record("reject.remote_orphan_artifact");
            Err(storage_failure(StorageFailureKind::IntegrityViolation))
        } else {
            Ok(())
        };
    };
    let expected_reason = match (status, publication) {
        (1, 1..=5) => Reason::ProviderOutputRejected,
        (1, 0) => Reason::ProviderAccountingUnknown,
        (2 | 3 | 5, _) => Reason::ProviderExecutionFailed,
        _ => {
            crate::store::test_support_diagnostics::record("reject.remote_status_disposition");
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    };
    if source_kind != 2
        || settlement_state != 3
        || artifact_status != status
        || i64::try_from(started.taskrun_version).ok() != Some(expected_taskrun_version)
        || conversation.as_slice() != started.conversation_id.as_bytes()
        || command.as_slice() != payload.command_id.as_bytes()
        || payload.conversation_events.len() != 1
        || !matches!(
            payload.conversation_events[0].payload(),
            runne_domain::conversation::ConversationEvent::GenerationFailed {
                taskrun_id,
                attempt_id,
                reason,
            } if *taskrun_id == started.taskrun_id
                && *attempt_id == started.attempt_id
                && *reason == expected_reason
        )
    {
        crate::store::test_support_diagnostics::record("reject.remote_source_fields");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let attempt = <[u8; 16]>::try_from(dispatch.as_slice()).map_err(|_| {
        crate::store::test_support_diagnostics::record("reject.remote_dispatch_id");
        storage_failure(StorageFailureKind::CorruptData)
    })?;
    let verified = crate::store::taskrun_submit_origin::verify_remote_terminal_taskrun_source(
        tx, &attempt, authority,
    )
    .map_err(|_| {
        crate::store::test_support_diagnostics::record("reject.remote_source_verification");
        storage_failure(StorageFailureKind::IntegrityViolation)
    })?;
    if !matches!(
        &verified.applicability,
        RemoteTerminalTaskRunApplicability::ActiveRunning { taskrun_version }
            if *taskrun_version == started.taskrun_version
    ) || verified.taskrun_id != started.taskrun_id
        || verified.taskrun_attempt_id != started.attempt_id
        || verified.conversation_id != started.conversation_id
        || verified.begin_command_id.as_bytes() != command.as_slice()
        || verified.writer_owner_principal != pinned_writer
    {
        crate::store::test_support_diagnostics::record("reject.remote_source_applicability");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if !verified.writer_lease_current {
        crate::store::test_support_diagnostics::record("reject.remote_writer_lease");
        return Err(storage_failure(StorageFailureKind::WriterFenced));
    }
    if !verified.publication_allowed {
        crate::store::test_support_diagnostics::record("reject.remote_publication_disallowed");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

pub(super) fn record_non_output_application(
    tx: &rusqlite::Transaction<'_>,
    started: &TextGenerationReceipt,
    payload: &RejectTextGenerationCommit,
) -> Result<(), CommitError> {
    use sha2::{Digest, Sha256};
    let source: Option<RemoteArtifactRejectIdentityRow> = tx
        .query_row(
            "SELECT s.dispatch_attempt_id,s.generation_id,s.begin_command_id,s.request_digest,
                    s.response_id_digest,s.artifact_digest,s.terminal_status,s.publication_disposition
             FROM provider_remote_terminal_settlements s
             WHERE s.taskrun_id=?1 AND s.taskrun_attempt_id=?2 AND s.source_kind=2",
            rusqlite::params![started.taskrun_id.as_bytes(), started.attempt_id.as_bytes()],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                    row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let Some((dispatch, generation, begin, request, response, artifact, status, publication)) =
        source
    else {
        return Ok(());
    };
    let reason = match payload
        .conversation_events
        .first()
        .map(|event| event.payload())
    {
        Some(runne_domain::conversation::ConversationEvent::GenerationFailed {
            reason, ..
        }) => reason.as_code(),
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    };
    let accounting_digest: Option<Vec<u8>> = tx
        .query_row(
            "SELECT settlement_digest FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1",
            [dispatch.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let accounting_state = if accounting_digest.is_some() {
        1_i64
    } else {
        2_i64
    };
    let digest_bytes = accounting_digest.as_deref();
    let (task_event, task_version) = (
        payload.taskrun_events[0].event_id().as_bytes().to_vec(),
        payload.receipt.taskrun_version,
    );
    let (conversation_event, conversation_version) = (
        payload.conversation_events[0]
            .event_id()
            .as_bytes()
            .to_vec(),
        payload.receipt.conversation_version,
    );
    let mut hash = Sha256::new();
    hash.update(b"gocode/provider/remote-terminal-application/v1\0");
    for value in [
        dispatch.as_slice(),
        started.taskrun_id.as_bytes(),
        started.attempt_id.as_bytes(),
        started.conversation_id.as_bytes(),
        generation.as_slice(),
        begin.as_slice(),
        request.as_slice(),
        response.as_slice(),
        artifact.as_slice(),
    ] {
        hash.update(value);
    }
    hash.update(status.to_be_bytes());
    hash.update(publication.to_be_bytes());
    hash.update(reason.as_bytes());
    hash.update(accounting_state.to_be_bytes());
    if let Some(value) = digest_bytes {
        hash.update(value);
    }
    hash.update(&task_event);
    hash.update(task_version.to_be_bytes());
    hash.update(&conversation_event);
    hash.update(conversation_version.to_be_bytes());
    // The receipt binds both the terminal conversation event and the
    // conversation head observed in the transaction. They currently name the
    // same failure event, but remain distinct fields in the canonical digest.
    hash.update(&conversation_event);
    hash.update(conversation_version.to_be_bytes());
    let application_digest: [u8; 32] = hash.finalize().into();
    tx.execute(
        "INSERT INTO provider_remote_terminal_applications(
            dispatch_attempt_id,taskrun_id,taskrun_attempt_id,conversation_id,
            generation_id,begin_command_id,request_digest,response_id_digest,artifact_digest,
            terminal_status,publication_disposition,failure_reason,accounting_state,
            accounting_digest,taskrun_terminal_event_id,taskrun_terminal_version,
            conversation_terminal_event_id,conversation_terminal_version,
            conversation_observed_event_id,conversation_observed_version,application_digest,created_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?17,?18,?19,unixepoch())",
        rusqlite::params![
            dispatch,
            started.taskrun_id.as_bytes().as_slice(),
            started.attempt_id.as_bytes().as_slice(),
            started.conversation_id.as_bytes().as_slice(),
            generation,
            begin,
            request,
            response,
            artifact,
            status,
            publication,
            reason,
            accounting_state,
            digest_bytes,
            task_event,
            i64::try_from(task_version).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
            conversation_event,
            i64::try_from(conversation_version).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
            application_digest.as_slice(),
        ],
    )
    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(())
}
