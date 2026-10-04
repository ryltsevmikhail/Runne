#[path = "v59_remote_terminal_source_readiness/finance.rs"]
mod finance;

fn v59_remote_terminal_source_rows_match(connection: &Connection) -> SqliteResult<bool> {
    let mut statement = connection.prepare(
        "SELECT s.dispatch_attempt_id,s.runtime_authority_id,s.settlement_state,
                s.settlement_digest,s.application_receipt_digest,d.state,
                d.settlement_digest,o.outbox_id,o.receipt_digest
         FROM provider_remote_terminal_settlements s
         JOIN provider_dispatch_attempts d ON d.attempt_id=s.dispatch_attempt_id
         JOIN provider_terminal_outbox o USING(dispatch_attempt_id)
         WHERE s.source_kind=2 AND s.settlement_state IN (2,4)
           AND s.publication_disposition=0",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(SourceReadinessRow {
            dispatch: row.get(0)?,
            authority: row.get(1)?,
            source_state: row.get(2)?,
            settlement_digest: row.get(3)?,
            application_digest: row.get(4)?,
            dispatch_state: row.get(5)?,
            dispatch_digest: row.get(6)?,
            outbox_id: row.get(7)?,
            outbox_receipt: row.get(8)?,
        })
    })?;
    for row in rows {
        let row = row?;
        let Some(verified) = source_identity(connection, &row)? else {
            return Ok(false);
        };
        if !finance::matches(connection, &row, &verified.original_principal)?
            || !typed_ack_matches(connection, &row, &verified)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

struct SourceReadinessRow {
    dispatch: Vec<u8>,
    authority: Vec<u8>,
    source_state: i64,
    settlement_digest: Vec<u8>,
    application_digest: Option<Vec<u8>>,
    dispatch_state: i64,
    dispatch_digest: Option<Vec<u8>>,
    outbox_id: Vec<u8>,
    outbox_receipt: Option<Vec<u8>>,
}

struct SourceReadinessPin {
    taskrun: Vec<u8>,
    attempt: Vec<u8>,
    conversation: Vec<u8>,
    writer_owner: String,
    writer_fence: i64,
    begin_command: Vec<u8>,
    generation: Vec<u8>,
    begin_digest: Vec<u8>,
    expected_version: i64,
}

fn source_identity(
    connection: &Connection,
    row: &SourceReadinessRow,
) -> SqliteResult<Option<crate::store::taskrun_submit_origin::VerifiedRemoteTerminalTaskRunSource>>
{
    let (Ok(dispatch), Ok(authority)) = (
        <[u8; 16]>::try_from(row.dispatch.as_slice()),
        <[u8; 16]>::try_from(row.authority.as_slice()),
    ) else {
        return Ok(None);
    };
    let pin = connection.query_row(
        "SELECT taskrun_id,taskrun_attempt_id,conversation_id,writer_owner_principal,
                writer_fencing_token,begin_command_id,generation_id,begin_event_digest,
                expected_taskrun_version
         FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
        [dispatch.as_slice()],
        |saved| {
            Ok(SourceReadinessPin {
                taskrun: saved.get(0)?,
                attempt: saved.get(1)?,
                conversation: saved.get(2)?,
                writer_owner: saved.get(3)?,
                writer_fence: saved.get(4)?,
                begin_command: saved.get(5)?,
                generation: saved.get(6)?,
                begin_digest: saved.get(7)?,
                expected_version: saved.get(8)?,
            })
        },
    )?;
    let authority = runne_application::ports::RuntimeAuthorityId(
        authority.iter().map(|byte| format!("{byte:02x}")).collect(),
    );
    let verified = match crate::store::taskrun_submit_origin::verify_remote_terminal_taskrun_source(
        connection, &dispatch, &authority,
    ) {
        Ok(verified) => verified,
        Err(_) => return Ok(None),
    };
    let matches = pin.taskrun.as_slice() == verified.taskrun_id.as_bytes()
        && pin.attempt.as_slice() == verified.taskrun_attempt_id.as_bytes()
        && pin.conversation.as_slice() == verified.conversation_id.as_bytes()
        && pin.writer_owner == verified.writer_owner_principal
        && u64::try_from(pin.writer_fence).ok() == Some(verified.writer_fencing_token)
        && pin.begin_command.as_slice() == verified.begin_command_id.as_bytes()
        && pin.generation == verified.generation_id
        && pin.begin_digest.as_slice() == verified.begin_event_digest
        && u64::try_from(pin.expected_version).ok() == Some(verified.expected_taskrun_version);
    let current_fence: Option<i64> = connection
        .query_row(
            "SELECT fencing_token FROM conversation_writer_leases WHERE conversation_id=?1",
            [pin.conversation.as_slice()],
            |lease| lease.get(0),
        )
        .optional()?;
    let writer_pin_is_monotonic = current_fence
        .and_then(|fence| u64::try_from(fence).ok())
        .is_some_and(|fence| fence >= verified.writer_fencing_token);
    let original_owner_is_pinned = verified.writer_fencing_token > 0
        && verified.writer_owner_principal == verified.original_principal;
    Ok((matches && writer_pin_is_monotonic && original_owner_is_pinned).then_some(verified))
}

fn typed_ack_matches(
    connection: &Connection,
    row: &SourceReadinessRow,
    verified: &crate::store::taskrun_submit_origin::VerifiedRemoteTerminalTaskRunSource,
) -> SqliteResult<bool> {
    let dispatch_state_matches = match row.source_state {
        2 => matches!(row.dispatch_state, 4 | 6),
        4 => matches!(row.dispatch_state, 5 | 6),
        _ => false,
    };
    if !dispatch_state_matches {
        return Ok(false);
    }
    let dispatch_digest_matches = match row.dispatch_state {
        4 | 5 => row.dispatch_digest.as_deref() == Some(row.settlement_digest.as_slice()),
        6 => row.dispatch_digest.is_none(),
        _ => false,
    };
    if !dispatch_digest_matches {
        return Ok(false);
    }
    if row.source_state == 2 {
        if row.application_digest.is_some() || row.outbox_receipt.is_some() {
            return Ok(false);
        }
        if matches!(
            &verified.applicability,
            crate::store::taskrun_submit_origin::RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion { .. }
        ) {
            let (Ok(outbox), Ok(attempt), Ok(settlement)) = (
                <[u8; 16]>::try_from(row.outbox_id.as_slice()),
                <[u8; 16]>::try_from(row.dispatch.as_slice()),
                <[u8; 32]>::try_from(row.settlement_digest.as_slice()),
            ) else {
                return Ok(false);
            };
            return Ok(
                crate::provider::validate_remote_artifact_pending_application_for_readiness(
                    connection, outbox, attempt, settlement, verified,
                )
                .unwrap_or(false),
            );
        }
        return Ok(true);
    }
    let (Ok(outbox), Ok(attempt), Ok(settlement), Some(Ok(receipt)), Some(application)) = (
        <[u8; 16]>::try_from(row.outbox_id.as_slice()),
        <[u8; 16]>::try_from(row.dispatch.as_slice()),
        <[u8; 32]>::try_from(row.settlement_digest.as_slice()),
        row.outbox_receipt.as_deref().map(<[u8; 32]>::try_from),
        row.application_digest.as_ref(),
    ) else {
        return Ok(false);
    };
    if application.as_slice() != receipt.as_slice() {
        return Ok(false);
    }
    match crate::provider::validate_remote_artifact_ack_for_readiness(
        connection, outbox, attempt, settlement, receipt, 4,
    ) {
        Ok(Some(crate::provider::RemoteArtifactAckKind::PublishedOutput))
        | Ok(Some(crate::provider::RemoteArtifactAckKind::AuditOnly)) => Ok(true),
        Ok(None) | Err(_) => Ok(false),
    }
}
