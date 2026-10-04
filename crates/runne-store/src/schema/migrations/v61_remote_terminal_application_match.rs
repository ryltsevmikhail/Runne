fn v61_rows_match(connection: &Connection) -> SqliteResult<bool> {
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_remote_terminal_applications a
         LEFT JOIN provider_remote_terminal_settlements s USING(dispatch_attempt_id)
         LEFT JOIN provider_remote_terminal_artifacts t USING(dispatch_attempt_id)
         LEFT JOIN provider_terminal_dispositions p USING(dispatch_attempt_id)
         LEFT JOIN provider_accounting_settlements f USING(dispatch_attempt_id)
         LEFT JOIN provider_terminal_outbox o USING(dispatch_attempt_id)
         WHERE s.dispatch_attempt_id IS NULL OR t.dispatch_attempt_id IS NULL
            OR s.settlement_state!=3 OR s.application_receipt_digest IS NOT NULL
            OR s.taskrun_id!=a.taskrun_id OR s.taskrun_attempt_id!=a.taskrun_attempt_id
            OR s.conversation_id!=a.conversation_id OR s.generation_id!=a.generation_id
            OR s.begin_command_id!=a.begin_command_id OR s.request_digest!=a.request_digest
            OR s.response_id_digest!=a.response_id_digest OR s.artifact_digest!=a.artifact_digest
            OR s.terminal_status!=a.terminal_status
            OR s.publication_disposition!=a.publication_disposition
            OR t.disposition!=a.terminal_status OR t.plaintext_digest!=a.artifact_digest
            OR o.dispatch_attempt_id IS NOT NULL
            OR (a.accounting_state=1 AND p.disposition IS NOT
                CASE a.terminal_status WHEN 1 THEN 4 WHEN 2 THEN 2 WHEN 3 THEN 3 WHEN 5 THEN 5 END)
            OR (a.accounting_state=2 AND p.disposition IS NOT NULL
                AND p.disposition IS NOT
                CASE a.terminal_status WHEN 1 THEN 4 WHEN 2 THEN 2 WHEN 3 THEN 3 WHEN 5 THEN 5 END)
            OR (a.accounting_state=1 AND (f.dispatch_attempt_id IS NULL
                OR f.settlement_digest!=a.accounting_digest
                OR f.pricing_revision_digest!=s.pricing_revision_digest
                OR f.input_tokens IS NOT s.input_tokens OR f.output_tokens IS NOT s.output_tokens
                OR f.cached_input_tokens IS NOT s.cached_input_tokens
                OR f.reasoning_output_tokens IS NOT s.reasoning_output_tokens))
            OR (a.accounting_state=2 AND (f.dispatch_attempt_id IS NOT NULL
                OR (SELECT COUNT(*) FROM provider_budget_reservations b
                    JOIN provider_dispatch_attempts d ON d.provider_idempotency_key=b.provider_idempotency_key
                    WHERE d.attempt_id=a.dispatch_attempt_id AND b.state=1)!=2))
            OR (a.terminal_status=1 AND a.publication_disposition!=0
                AND a.failure_reason!='provider_output_rejected')
            OR (a.terminal_status=1 AND a.publication_disposition=0
                AND a.accounting_state=2 AND a.failure_reason!='provider_accounting_unknown')
            OR (a.terminal_status IN (2,3,5) AND a.failure_reason!='provider_execution_failed')",
        [],
        |row| row.get(0),
    )?;
    if invalid != 0 {
        return Ok(false);
    }
    let mut statement = connection.prepare(
        "SELECT dispatch_attempt_id,taskrun_id,taskrun_attempt_id,conversation_id,
                generation_id,begin_command_id,request_digest,response_id_digest,artifact_digest,
                terminal_status,publication_disposition,failure_reason,accounting_state,
                accounting_digest,taskrun_terminal_event_id,taskrun_terminal_version,
                conversation_terminal_event_id,conversation_terminal_version,
                conversation_observed_event_id,conversation_observed_version,application_digest
         FROM provider_remote_terminal_applications",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Vec<u8>>(6)?,
            row.get::<_, Vec<u8>>(7)?,
            row.get::<_, Vec<u8>>(8)?,
            row.get::<_, i64>(9)?,
            row.get::<_, i64>(10)?,
            row.get::<_, String>(11)?,
            row.get::<_, i64>(12)?,
            row.get::<_, Option<Vec<u8>>>(13)?,
            row.get::<_, Vec<u8>>(14)?,
            row.get::<_, i64>(15)?,
            row.get::<_, Option<Vec<u8>>>(16)?,
            row.get::<_, Option<i64>>(17)?,
            row.get::<_, Vec<u8>>(18)?,
            row.get::<_, i64>(19)?,
            row.get::<_, Vec<u8>>(20)?,
        ))
    })?;
    for row in rows {
        let row = row?;
        if !v61_application_row_matches(connection, &row)? {
            return Ok(false);
        }
    }
    Ok(true)
}

type V61ApplicationRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    String,
    i64,
    Option<Vec<u8>>,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Option<i64>,
    Vec<u8>,
    i64,
    Vec<u8>,
);

fn v61_application_row_matches(
    connection: &Connection,
    row: &V61ApplicationRow,
) -> SqliteResult<bool> {
    use sha2::{Digest, Sha256};
    let (
        dispatch,
        taskrun,
        attempt,
        conversation,
        generation,
        begin,
        request,
        response,
        artifact,
        status,
        publication,
        reason,
        accounting_state,
        accounting_digest,
        task_event,
        task_version,
        conversation_event,
        conversation_version,
        observed_event,
        observed_version,
        digest,
    ) = row;
    let fixed = |value: &[u8], size: usize| value.len() == size && value.iter().any(|b| *b != 0);
    if ![
        dispatch,
        taskrun,
        attempt,
        conversation,
        begin,
        task_event,
        observed_event,
    ]
    .iter()
    .all(|value| fixed(value, 16))
        || !fixed(generation, 16)
        || ![request, response, artifact, digest]
            .iter()
            .all(|value| fixed(value, 32))
        || accounting_digest
            .as_ref()
            .is_some_and(|value| !fixed(value, 32))
        || *task_version <= 0
        || *observed_version <= 0
        || conversation_event.is_some() != conversation_version.is_some()
        || conversation_event
            .as_ref()
            .is_some_and(|value| !fixed(value, 16))
        || conversation_version.is_some_and(|value| value <= 0)
    {
        return Ok(false);
    }
    let task_payload = v61_event_payload(connection, 1, taskrun, task_event, *task_version)?;
    let task = crate::codec::TaskRunEventCodec
        .decode(&task_payload)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let expected_reason = match reason.as_str() {
        "provider_output_rejected" => {
            runne_domain::conversation::GenerationFailureReason::ProviderOutputRejected
        }
        "provider_execution_failed" => {
            runne_domain::conversation::GenerationFailureReason::ProviderExecutionFailed
        }
        "provider_accounting_unknown" => {
            runne_domain::conversation::GenerationFailureReason::ProviderAccountingUnknown
        }
        _ => return Ok(false),
    };
    if !matches!(task, runne_domain::task_run::TaskRunEvent::TaskRunFailed { reason: ref value } if value == reason)
    {
        return Ok(false);
    }
    let conversation_valid = match (conversation_event, conversation_version) {
        (Some(event), Some(version)) => {
            if event != observed_event || *version != *observed_version {
                false
            } else {
                let payload = v61_event_payload(connection, 2, conversation, event, *version)?;
                let decoded = crate::codec::ConversationEventCodec
                    .decode(&payload)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                matches!(decoded,
                    runne_domain::conversation::ConversationEvent::GenerationFailed { taskrun_id, attempt_id, reason: event_reason }
                        if taskrun_id.as_bytes() == taskrun.as_slice()
                            && attempt_id.as_bytes() == attempt.as_slice()
                            && event_reason == expected_reason)
            }
        }
        (None, None) => v61_has_successor_generation(
            connection,
            conversation,
            taskrun,
            attempt,
            observed_event,
            *observed_version,
        )?,
        _ => false,
    };
    if !conversation_valid {
        return Ok(false);
    }
    let mut hash = Sha256::new();
    hash.update(b"gocode/provider/remote-terminal-application/v1\0");
    for value in [
        dispatch,
        taskrun,
        attempt,
        conversation,
        generation,
        begin,
        request,
        response,
        artifact,
    ] {
        hash.update(value);
    }
    hash.update(status.to_be_bytes());
    hash.update(publication.to_be_bytes());
    hash.update(reason.as_bytes());
    hash.update(accounting_state.to_be_bytes());
    if let Some(value) = accounting_digest {
        hash.update(value);
    }
    hash.update(task_event);
    hash.update(task_version.to_be_bytes());
    if let Some(event) = conversation_event {
        hash.update(event);
    }
    if let Some(version) = conversation_version {
        hash.update(version.to_be_bytes());
    }
    hash.update(observed_event);
    hash.update(observed_version.to_be_bytes());
    let expected: [u8; 32] = hash.finalize().into();
    Ok(expected.as_slice() == digest.as_slice())
}

fn v61_event_payload(
    connection: &Connection,
    aggregate_type: i64,
    aggregate_id: &[u8],
    event_id: &[u8],
    version: i64,
) -> SqliteResult<Vec<u8>> {
    connection.query_row(
        "SELECT payload FROM events WHERE aggregate_type=?1 AND aggregate_id=?2
         AND event_id=?3 AND sequence=?4",
        rusqlite::params![aggregate_type, aggregate_id, event_id, version],
        |row| row.get(0),
    )
}
