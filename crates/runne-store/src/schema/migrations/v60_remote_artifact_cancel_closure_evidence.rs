struct V60CancelCommandReceiptFacts<'a> {
    taskrun: &'a [u8],
    cancel_command: &'a [u8],
    cancellation_key: &'a [u8],
    cancellation_actor: &'a str,
    original_principal: &'a str,
    original_actor: &'a str,
    cancel_version: &'a i64,
    authority_id: &'a [u8; 16],
}

fn v60_cancel_command_receipt_matches(
    connection: &Connection,
    facts: V60CancelCommandReceiptFacts<'_>,
) -> SqliteResult<bool> {
    let V60CancelCommandReceiptFacts {
        taskrun,
        cancel_command,
        cancellation_key,
        cancellation_actor,
        original_principal,
        original_actor,
        cancel_version,
        authority_id,
    } = facts;
    let (scope_bytes, idempotency_key, fingerprint_bytes, outcome_bytes): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = connection.query_row(
        "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome
             FROM command_receipts WHERE command_id=?1",
        [cancel_command],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let scope = crate::codec::IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let taskrun_id = runne_domain::id::TaskRunId::from_bytes(
        taskrun
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    );
    let expected_fingerprint = runne_application::fingerprint::CommandFingerprint::for_cancel(
        &taskrun_id,
        u64::try_from(*cancel_version - 1).map_err(|_| rusqlite::Error::InvalidQuery)?,
    );
    let outcome = crate::codec::CommandOutcomeCodec
        .decode(&outcome_bytes)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(
        scope.operation == runne_application::ports::OperationTag::CancelTaskRun
            && scope.runtime_authority_id.0 == v60_hex_authority(authority_id)
            && scope.aggregate_scope
                == (runne_application::ports::AggregateScope::ExistingTaskRun { taskrun_id })
            && scope.principal_id.0 == original_principal
            && cancellation_actor == original_actor
            && cancellation_key == idempotency_key
            && fingerprint_bytes == expected_fingerprint.as_bytes()
            && outcome
                == (runne_application::commands::CommandOutcome::TaskRunCancellationRequested {
                    taskrun_id,
                    new_version: u64::try_from(*cancel_version)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                }),
    )
}

struct V60ConversationWitnessFacts<'a> {
    conversation: &'a [u8],
    taskrun: &'a [u8],
    attempt: &'a [u8],
    observed_event: &'a [u8],
    observed_version: i64,
    terminal_event: Option<&'a [u8]>,
    terminal_version: Option<i64>,
}

fn v60_conversation_witness_matches(
    connection: &Connection,
    facts: V60ConversationWitnessFacts<'_>,
) -> SqliteResult<bool> {
    let V60ConversationWitnessFacts {
        conversation,
        taskrun,
        attempt,
        observed_event,
        observed_version,
        terminal_event,
        terminal_version,
    } = facts;
    let observed_payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1
             AND event_id=?2 AND sequence=?3",
            rusqlite::params![conversation, observed_event, observed_version],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or_default();
    if observed_payload.is_empty() {
        return Ok(false);
    }
    let observed = crate::codec::ConversationEventCodec
        .decode(&observed_payload)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    if !matches!(
        observed,
        runne_domain::conversation::ConversationEvent::UserMessageAppended {
            taskrun_id: source_taskrun,
            attempt_id: source_attempt,
            ..
        } if source_taskrun.as_bytes() == taskrun && source_attempt.as_bytes() == attempt
    ) {
        return Ok(false);
    }
    let head: (i64, Option<Vec<u8>>) = connection.query_row(
        "SELECT current_version,last_event_id FROM aggregate_streams
         WHERE aggregate_type=2 AND aggregate_id=?1",
        [conversation],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    match (terminal_event, terminal_version) {
        (Some(event_id), Some(version)) => {
            if version != observed_version + 1 || head.0 < version || head.1.is_none() {
                return Ok(false);
            }
            let bytes: Vec<u8> = connection
                .query_row(
                    "SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1
                 AND event_id=?2 AND sequence=?3 AND causation_id=?4",
                    rusqlite::params![conversation, event_id, version, observed_event],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or_default();
            let event = crate::codec::ConversationEventCodec
                .decode(&bytes)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(matches!(
                event,
                runne_domain::conversation::ConversationEvent::GenerationFailed {
                    taskrun_id: source_taskrun,
                    attempt_id: source_attempt,
                    reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
                } if source_taskrun.as_bytes() == taskrun && source_attempt.as_bytes() == attempt
            ))
        }
        (None, None) => {
            if head.0 <= observed_version {
                return Ok(false);
            }
            let mut statement = connection.prepare(
                "SELECT event_id,sequence,payload FROM events
                 WHERE aggregate_type=2 AND aggregate_id=?1 AND sequence>?2 ORDER BY sequence",
            )?;
            let rows =
                statement.query_map(rusqlite::params![conversation, observed_version], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })?;
            for row in rows {
                let (event_id, sequence, bytes) = row?;
                let event = crate::codec::ConversationEventCodec
                    .decode(&bytes)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                if let runne_domain::conversation::ConversationEvent::GenerationSupersededUnknown {
                    taskrun_id: predecessor,
                    attempt_id: predecessor_attempt,
                    successor_taskrun_id,
                    acknowledgement_digest,
                } = event
                    && predecessor.as_bytes() == taskrun
                    && predecessor_attempt.as_bytes() == attempt
                {
                    let exact = connection.query_row(
                        "SELECT EXISTS(SELECT 1 FROM taskrun_unknown_successor_receipts
                         WHERE predecessor_taskrun_id=?1 AND successor_taskrun_id=?2
                           AND conversation_id=?3 AND generation_superseded_event_id=?4
                           AND generation_superseded_version=?5 AND acknowledgement_digest=?6)",
                        rusqlite::params![
                            taskrun,
                            successor_taskrun_id.as_bytes(),
                            conversation,
                            event_id,
                            sequence,
                            acknowledgement_digest.as_bytes()
                        ],
                        |row| row.get::<_, bool>(0),
                    )?;
                    return Ok(exact);
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}
