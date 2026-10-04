fn persist_remote_terminal_audit_receipt(
    transaction: &Transaction<'_>,
    request: &runne_runtime::provider_execution::ProviderRemoteTerminalSourceCommit,
    verified: &crate::store::taskrun_submit_origin::VerifiedRemoteTerminalTaskRunSource,
) -> Result<(), ProviderExecutionError> {
    use crate::schema::{V62AuditDigestFields, v62_audit_digest, v62_valid_audit_for_source};
    use crate::store::taskrun_submit_origin::RemoteTerminalTaskRunApplicability;

    if v62_valid_audit_for_source(
        transaction,
        crate::schema::RemoteTerminalSourceMatch {
            dispatch: request.attempt_id().as_bytes(),
            taskrun: request.taskrun_id().as_bytes(),
            attempt: request.taskrun_attempt_id().as_bytes(),
            request: request.request_digest().as_slice(),
            response: request.response_id_digest().as_slice(),
            artifact: request.artifact_digest().as_slice(),
            status: request.terminal_status().code(),
        },
    )
    .map_err(|_| ProviderExecutionError::StoreUnavailable)?
    {
        return Ok(());
    }
    let (witness_kind, terminal, successor, supersession, release, release_reason, ack, fence) =
        match &verified.applicability {
            RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion {
                terminal_event_id,
                terminal_version,
                release_reason,
                ..
            } => {
                let fence: i64 = transaction
                    .query_row(
                        "SELECT fence FROM taskrun_terminal_settlement_receipts
                         WHERE taskrun_id=?1 AND attempt_id=?2 AND terminal_event_id=?3
                           AND terminal_version=?4",
                        rusqlite::params![
                            request.taskrun_id().as_bytes().as_slice(),
                            request.taskrun_attempt_id().as_bytes().as_slice(),
                            terminal_event_id.as_slice(),
                            i64::try_from(*terminal_version)
                                .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|_| ProviderExecutionError::TerminalConflict)?;
                (
                    1_i64,
                    Some((*terminal_event_id, *terminal_version)),
                    None,
                    None,
                    (*terminal_event_id, *terminal_version),
                    release_reason.as_str(),
                    None,
                    fence,
                )
            }
            RemoteTerminalTaskRunApplicability::ExactUserSupersession {
                successor_taskrun_id,
                release_event_id,
                release_version,
                ..
            } => {
                let (successor_submit, successor_version, ack, fence): (
                    Vec<u8>,
                    i64,
                    Vec<u8>,
                    i64,
                ) = transaction
                    .query_row(
                        "SELECT successor_submit_event_id,successor_submit_version,
                                acknowledgement_digest,occupation_fence
                         FROM taskrun_unknown_successor_receipts
                         WHERE predecessor_taskrun_id=?1 AND predecessor_attempt_id=?2
                           AND predecessor_dispatch_attempt_id=?3 AND successor_taskrun_id=?4
                           AND occupation_release_event_id=?5 AND occupation_release_version=?6
                           AND occupation_release_reason='user_supersession'",
                        rusqlite::params![
                            request.taskrun_id().as_bytes().as_slice(),
                            request.taskrun_attempt_id().as_bytes().as_slice(),
                            request.attempt_id().as_bytes().as_slice(),
                            successor_taskrun_id.as_bytes().as_slice(),
                            release_event_id.as_slice(),
                            i64::try_from(*release_version)
                                .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                        ],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .map_err(|_| ProviderExecutionError::TerminalConflict)?;
                let successor_submit = fixed_v62::<16>(successor_submit)?;
                let ack = fixed_v62::<32>(ack)?;
                (
                    2_i64,
                    None,
                    Some((
                        *successor_taskrun_id.as_bytes(),
                        successor_submit,
                        u64::try_from(successor_version)
                            .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                    )),
                    Some((*release_event_id, *release_version)),
                    (*release_event_id, *release_version),
                    "user_supersession",
                    Some(ack),
                    fence,
                )
            }
            _ => return Ok(()),
        };
    if release_reason != "terminal_settlement" && release_reason != "user_supersession" {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let (conversation_event, conversation_version): (Vec<u8>, i64) = transaction
        .query_row(
            "SELECT event_id,sequence FROM events WHERE aggregate_type=2 AND aggregate_id=?1
             ORDER BY sequence DESC LIMIT 1",
            [verified.conversation_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| ProviderExecutionError::TerminalConflict)?;
    let accounting_digest: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT settlement_digest FROM provider_accounting_settlements
             WHERE dispatch_attempt_id=?1",
            [request.attempt_id().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let accounting_state = if accounting_digest.is_some() {
        1_i64
    } else {
        2_i64
    };
    let fixed_optional =
        |value: Option<&[u8]>| -> Result<Option<[u8; 32]>, ProviderExecutionError> {
            value.map(fixed_v62_slice::<32>).transpose()
        };
    let terminal_event = terminal.map(|value| value.0);
    let terminal_version = terminal
        .map(|value| i64::try_from(value.1).map_err(|_| ProviderExecutionError::TerminalConflict))
        .transpose()?;
    let successor_taskrun = successor.map(|value| value.0);
    let successor_submit_event = successor.map(|value| value.1);
    let successor_submit_version = successor
        .map(|value| i64::try_from(value.2).map_err(|_| ProviderExecutionError::TerminalConflict))
        .transpose()?;
    let supersession_event = supersession.map(|value| value.0);
    let supersession_version = supersession
        .map(|value| i64::try_from(value.1).map_err(|_| ProviderExecutionError::TerminalConflict))
        .transpose()?;
    let conversation_event = fixed_v62::<16>(conversation_event)?;
    let accounting_digest_fixed = fixed_optional(accounting_digest.as_deref())?;
    let fields = V62AuditDigestFields {
        dispatch: *request.attempt_id().as_bytes(),
        taskrun: *request.taskrun_id().as_bytes(),
        attempt: *request.taskrun_attempt_id().as_bytes(),
        conversation: *verified.conversation_id.as_bytes(),
        request: *request.request_digest(),
        response: *request.response_id_digest(),
        artifact: *request.artifact_digest(),
        terminal_status: request.terminal_status().code(),
        witness_kind,
        terminal_event,
        terminal_version,
        successor_taskrun,
        successor_submit_event,
        successor_submit_version,
        supersession_event,
        supersession_version,
        release_event: release.0,
        release_version: i64::try_from(release.1)
            .map_err(|_| ProviderExecutionError::TerminalConflict)?,
        release_fence: fence,
        release_reason: release_reason.to_owned(),
        acknowledgement: ack,
        conversation_observed_event: conversation_event,
        conversation_observed_version: conversation_version,
        accounting_state,
        accounting_digest: accounting_digest_fixed,
    };
    let digest = v62_audit_digest(&fields);
    let existing: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT audit_digest FROM provider_remote_terminal_audit_receipts
             WHERE dispatch_attempt_id=?1",
            [request.attempt_id().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if let Some(existing) = existing {
        return if existing.as_slice() == digest {
            Ok(())
        } else {
            Err(ProviderExecutionError::TerminalConflict)
        };
    }
    transaction
        .execute(
            "INSERT INTO provider_remote_terminal_audit_receipts(
                dispatch_attempt_id,taskrun_id,taskrun_attempt_id,conversation_id,
                request_digest,response_id_digest,artifact_digest,terminal_status,witness_kind,
                terminal_event_id,terminal_version,successor_taskrun_id,successor_submit_event_id,
                successor_submit_version,supersession_event_id,supersession_version,
                release_event_id,release_version,release_fence,release_reason,
                acknowledgement_digest,conversation_observed_event_id,conversation_observed_version,
                accounting_state,accounting_digest,audit_digest,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,
                    ?19,?20,?21,?22,?23,?24,?25,?26,unixepoch())",
            rusqlite::params![
                fields.dispatch.as_slice(),
                fields.taskrun.as_slice(),
                fields.attempt.as_slice(),
                fields.conversation.as_slice(),
                fields.request.as_slice(),
                fields.response.as_slice(),
                fields.artifact.as_slice(),
                fields.terminal_status,
                fields.witness_kind,
                fields.terminal_event.as_ref().map(|value| value.as_slice()),
                fields.terminal_version,
                fields
                    .successor_taskrun
                    .as_ref()
                    .map(|value| value.as_slice()),
                fields
                    .successor_submit_event
                    .as_ref()
                    .map(|value| value.as_slice()),
                fields.successor_submit_version,
                fields
                    .supersession_event
                    .as_ref()
                    .map(|value| value.as_slice()),
                fields.supersession_version,
                fields.release_event.as_slice(),
                fields.release_version,
                fields.release_fence,
                fields.release_reason,
                fields
                    .acknowledgement
                    .as_ref()
                    .map(|value| value.as_slice()),
                fields.conversation_observed_event.as_slice(),
                fields.conversation_observed_version,
                fields.accounting_state,
                fields
                    .accounting_digest
                    .as_ref()
                    .map(|value| value.as_slice()),
                digest.as_slice(),
            ],
        )
        .map_err(|_| ProviderExecutionError::TerminalConflict)?;
    Ok(())
}

fn fixed_v62<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], ProviderExecutionError> {
    bytes
        .try_into()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn fixed_v62_slice<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProviderExecutionError> {
    bytes
        .try_into()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}
