fn v60_rows_match(connection: &Connection) -> SqliteResult<bool> {
    let mut statement = connection.prepare(
        "SELECT c.dispatch_attempt_id,c.taskrun_id,c.taskrun_attempt_id,c.conversation_id,
                c.artifact_digest,c.terminal_status,c.cancellation_command_id,
                c.cancellation_event_id,c.cancellation_taskrun_version,
                c.taskrun_terminal_event_id,c.taskrun_terminal_version,
                c.observed_conversation_head_event_id,c.observed_conversation_head_version,
                c.conversation_terminal_event_id,c.conversation_terminal_version,c.closure_digest,
                s.taskrun_id,s.taskrun_attempt_id,s.conversation_id,s.artifact_digest,s.terminal_status
         FROM provider_remote_artifact_cancel_closures c
         LEFT JOIN provider_remote_terminal_settlements s USING(dispatch_attempt_id)",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, Vec<u8>>(6)?,
            row.get::<_, Vec<u8>>(7)?,
            row.get::<_, i64>(8)?,
            row.get::<_, Vec<u8>>(9)?,
            row.get::<_, i64>(10)?,
            row.get::<_, Vec<u8>>(11)?,
            row.get::<_, i64>(12)?,
            row.get::<_, Option<Vec<u8>>>(13)?,
            row.get::<_, Option<i64>>(14)?,
            row.get::<_, Vec<u8>>(15)?,
            row.get::<_, Option<Vec<u8>>>(16)?,
            row.get::<_, Option<Vec<u8>>>(17)?,
            row.get::<_, Option<Vec<u8>>>(18)?,
            row.get::<_, Option<Vec<u8>>>(19)?,
            row.get::<_, Option<i64>>(20)?,
        ))
    })?;
    for row in rows {
        let row = row?;
        if !v60_closure_row_matches(connection, &row)? {
            return Ok(false);
        }
    }
    Ok(true)
}

type V60ClosureRow = (
    Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, i64,
    Vec<u8>, i64, Option<Vec<u8>>, Option<i64>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>,
    Option<Vec<u8>>, Option<Vec<u8>>, Option<i64>,
);

fn v60_closure_row_matches(
    connection: &Connection,
    row: &V60ClosureRow,
) -> SqliteResult<bool> {
    use sha2::{Digest, Sha256};
    let fixed =
        |bytes: &[u8], len: usize| bytes.len() == len && bytes.iter().any(|byte| *byte != 0);
    let (
        dispatch,
        taskrun,
        attempt,
        conversation,
        artifact,
        status,
        cancel_command,
        cancel_event,
        cancel_version,
        terminal_event,
        terminal_version,
        observed_event,
        observed_version,
        conversation_event,
        conversation_version,
        digest,
        source_taskrun,
        source_attempt,
        source_conversation,
        source_artifact,
        source_status,
    ) = row;
    if !fixed(dispatch, 16)
        || !fixed(taskrun, 16)
        || !fixed(attempt, 16)
        || !fixed(conversation, 16)
        || !fixed(artifact, 32)
        || !fixed(cancel_command, 16)
        || !fixed(cancel_event, 16)
        || !fixed(terminal_event, 16)
        || !fixed(observed_event, 16)
        || !fixed(digest, 32)
        || !matches!(*status, 1 | 2 | 3 | 5)
        || *cancel_version <= 0
        || *terminal_version <= *cancel_version
        || *observed_version <= 0
        || conversation_event.as_ref().is_some_and(|id| !fixed(id, 16))
        || conversation_version.is_some_and(|version| version <= *observed_version)
        || conversation_event.is_some() != conversation_version.is_some()
        || source_taskrun.as_deref() != Some(taskrun.as_slice())
        || source_attempt.as_deref() != Some(attempt.as_slice())
        || source_conversation.as_deref() != Some(conversation.as_slice())
        || source_artifact.as_deref() != Some(artifact.as_slice())
        || source_status != &Some(*status)
    {
        return Ok(false);
    }
    let dispatch_id: [u8; 16] = dispatch
        .as_slice()
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let authority = connection.query_row(
        "SELECT runtime_authority_id FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
        [dispatch.as_slice()], |row| row.get::<_,Vec<u8>>(0),
    )?;
    let authority_id: [u8; 16] = authority
        .as_slice()
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let verified = crate::store::taskrun_submit_origin::verify_remote_terminal_taskrun_source(
        connection,
        &dispatch_id,
        &runne_application::ports::RuntimeAuthorityId(v60_hex_authority(&authority_id)),
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let runne_store_event = connection.query_row(
        "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1
         AND event_id=?2 AND sequence=?3",
        rusqlite::params![
            taskrun.as_slice(),
            terminal_event.as_slice(),
            *terminal_version
        ],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let terminal_payload = crate::codec::TaskRunEventCodec
        .decode(&runne_store_event)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let (cancellation_bytes, cancellation_command_id, cancellation_key, cancellation_actor_bytes):
        (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT payload,command_id,idempotency_key,actor FROM events WHERE aggregate_type=1 AND aggregate_id=?1
         AND event_id=?2 AND sequence=?3",
        rusqlite::params![taskrun.as_slice(), cancel_event.as_slice(), *cancel_version],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let cancellation_actor =
        String::from_utf8(cancellation_actor_bytes).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let cancellation_payload = crate::codec::TaskRunEventCodec
        .decode(&cancellation_bytes)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let applicability_matches = matches!(
        &verified.applicability,
        crate::store::taskrun_submit_origin::RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion {
            taskrun_state: runne_domain::task_run::TaskRunState::Cancelled,
            terminal_event_id,
            terminal_version: version,
            terminal_payload,
            ..
        } if terminal_event_id.as_slice() == terminal_event.as_slice()
            && i64::try_from(*version).ok() == Some(*terminal_version)
            && matches!(terminal_payload.as_ref(), runne_domain::task_run::TaskRunEvent::CancellationCompleted)
    );
    if !applicability_matches
        || terminal_payload != runne_domain::task_run::TaskRunEvent::CancellationCompleted
        || cancellation_payload != runne_domain::task_run::TaskRunEvent::CancellationRequested
        || cancellation_command_id.as_slice() != cancel_command.as_slice()
    {
        return Ok(false);
    }
    if !v60_cancel_command_receipt_matches(
        connection,
        V60CancelCommandReceiptFacts {
            taskrun,
            cancel_command,
            cancellation_key: &cancellation_key,
            cancellation_actor: &cancellation_actor,
            original_principal: &verified.original_principal,
            original_actor: &verified.original_actor,
            cancel_version,
            authority_id: &authority_id,
        },
    )? {
        return Ok(false);
    }
    if !v60_conversation_witness_matches(
        connection,
        V60ConversationWitnessFacts {
            conversation,
            taskrun,
            attempt,
            observed_event,
            observed_version: *observed_version,
            terminal_event: conversation_event.as_deref(),
            terminal_version: *conversation_version,
        },
    )? {
        return Ok(false);
    }
    let mut hash = Sha256::new();
    hash.update(b"gocode/provider/remote-artifact-cancel-closure/v1\0");
    hash.update(dispatch);
    hash.update(taskrun);
    hash.update(attempt);
    hash.update(conversation);
    hash.update(artifact);
    hash.update(status.to_be_bytes());
    hash.update(cancel_command);
    hash.update(cancel_event);
    hash.update(cancel_version.to_be_bytes());
    hash.update(terminal_event);
    hash.update(terminal_version.to_be_bytes());
    hash.update(observed_event);
    hash.update(observed_version.to_be_bytes());
    if let (Some(event), Some(version)) = (conversation_event, conversation_version) {
        hash.update(event);
        hash.update(version.to_be_bytes());
    }
    let expected: [u8; 32] = hash.finalize().into();
    Ok(expected.as_slice() == digest.as_slice())
}
