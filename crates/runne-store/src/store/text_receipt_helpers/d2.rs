use super::*;

type D2CompletionLinkage = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

pub(super) fn validate_d2_completed_receipt(
    connection: &Connection,
    command_id: CommandId,
    receipt: &TextGenerationReceipt,
) -> Result<bool, CommitError> {
    let linkage: Option<D2CompletionLinkage> = connection
        .query_row(
            "SELECT taskrun_id,attempt_id,cycle_id,taskrun_head,evaluation_digest,terminal_outbox_id,assistant_text_digest,
                    terminal_attempt_id,terminal_sequence,settlement_digest,assistant_message_id,terminal_sources,completed_receipt_digest
             FROM d2_tool_loop_completions WHERE command_id=?1",
            [command_id.as_bytes()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?)),
        )
        .optional()
        .map_err(map_commit_read_error)?;
    let Some((
        taskrun,
        attempt,
        cycle,
        head,
        evaluation,
        outbox,
        text_digest,
        terminal_attempt,
        terminal_sequence,
        settlement,
        message_id,
        sources,
        stored_receipt_digest,
    )) = linkage
    else {
        return Ok(false);
    };
    let encoded = TextGenerationReceiptCodec
        .encode(receipt)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let receipt_digest: [u8; 32] = Sha256::digest(&encoded).into();
    let linked: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM d2_tool_loop_completions c
             JOIN provider_terminal_outbox o ON o.outbox_id=c.terminal_outbox_id
                AND o.dispatch_attempt_id=c.terminal_attempt_id AND o.terminal_sequence=c.terminal_sequence
                AND o.settlement_digest=c.settlement_digest
             JOIN provider_terminal_application_kinds k ON k.outbox_id=o.outbox_id AND k.dispatch_attempt_id=o.dispatch_attempt_id
             WHERE c.command_id=?1 AND c.taskrun_id=?2 AND c.attempt_id=?3 AND c.taskrun_head=?4
               AND c.terminal_outbox_id=?5 AND c.completed_receipt_digest=?6
               AND c.assistant_message_id=?7 AND c.assistant_text_digest=?8
               AND o.plaintext_digest=c.assistant_text_digest
               AND o.state=2 AND o.receipt_digest=?6 AND k.application_kind=2
               AND EXISTS(SELECT 1 FROM provider_dispatch_attempts d WHERE d.attempt_id=c.terminal_attempt_id AND d.settlement_digest=c.settlement_digest AND d.state=5)
               AND EXISTS(SELECT 1 FROM provider_terminal_dispositions t WHERE t.dispatch_attempt_id=c.terminal_attempt_id AND t.disposition=1)
               AND EXISTS(SELECT 1 FROM provider_stream_journal j WHERE j.dispatch_attempt_id=c.terminal_attempt_id AND j.sequence=c.terminal_sequence AND j.event_kind=5 AND j.terminal=1 AND j.profile_digest=o.profile_digest AND j.runtime_generation=o.runtime_generation AND j.key_id=o.key_id AND j.key_version=o.key_version))",
            params![command_id.as_bytes(),taskrun.as_slice(),attempt.as_slice(),head,outbox.as_slice(),receipt_digest.as_slice(),message_id.as_slice(),text_digest.as_slice()],
            |row| row.get(0),
        )
        .map_err(map_commit_read_error)?;
    if !linked
        || taskrun.as_slice() != receipt.taskrun_id.as_bytes()
        || attempt.as_slice() != receipt.attempt_id.as_bytes()
        || head != receipt.taskrun_version as i64
        || terminal_attempt.len() != 16
        || terminal_sequence <= 0
        || settlement.len() != 32
        || message_id.as_slice() != receipt.assistant_message_id.as_bytes()
        || stored_receipt_digest.as_slice() != receipt_digest.as_slice()
        || !validate_d2_sources(connection, &terminal_attempt, &sources)?
    {
        return Ok(false);
    }
    let terminal: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2",
            params![
                receipt.taskrun_id.as_bytes(),
                receipt.taskrun_version as i64
            ],
            |row| row.get(0),
        )
        .map_err(map_commit_read_error)?;
    let terminal = TaskRunEventCodec
        .decode(&terminal)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !matches!(
        terminal,
        TaskRunEvent::TaskRunCompleted {
            result: runne_domain::command::TerminalResult::Success
        }
    ) {
        return Ok(false);
    }
    let mut statement = connection
        .prepare("SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence<?2 ORDER BY sequence")
        .map_err(map_commit_read_error)?;
    let rows = statement
        .query_map(
            params![
                receipt.taskrun_id.as_bytes(),
                receipt.taskrun_version as i64
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(map_commit_read_error)?;
    let mut exact_evaluation = false;
    for row in rows {
        let event = TaskRunEventCodec
            .decode(&row.map_err(map_commit_read_error)?)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if let TaskRunEvent::LoopCycleCompleted {
            cycle_id,
            attempt_id,
            disposition:
                runne_domain::agent_loop::LoopDisposition::Complete {
                    plan_evaluation_ref,
                },
        } = event
            && cycle_id.as_bytes() == cycle.as_slice()
            && attempt_id == receipt.attempt_id
            && plan_evaluation_ref.evaluation_digest.as_bytes() == evaluation.as_slice()
        {
            exact_evaluation = true;
        }
    }
    if !exact_evaluation {
        return Ok(false);
    }
    let assistant: Option<Vec<u8>> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1 AND sequence=?2",
            params![
                receipt.conversation_id.as_bytes(),
                receipt.conversation_version as i64
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_commit_read_error)?;
    let Some(payload) = assistant else {
        return Ok(false);
    };
    let event = ConversationEventCodec
        .decode(&payload)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let (matches, expected_length) = match &event {
        ConversationEvent::AssistantMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            text,
        } => (
            *message_id == receipt.assistant_message_id
                && *taskrun_id == receipt.taskrun_id
                && *attempt_id == receipt.attempt_id
                && Sha256::digest(text.as_str().as_bytes()).as_slice() == text_digest.as_slice(),
            i64::try_from(text.as_str().len())
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
        ),
        _ => return Ok(false),
    };
    let text_length: Option<i64> = connection
        .query_row(
            "SELECT o.plaintext_len FROM d2_tool_loop_completions c
             JOIN provider_terminal_outbox o ON o.outbox_id=c.terminal_outbox_id
             WHERE c.command_id=?1",
            [command_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_commit_read_error)?;
    Ok(matches && text_length == Some(expected_length))
}

fn validate_d2_sources(
    connection: &Connection,
    terminal_attempt: &[u8],
    encoded: &[u8],
) -> Result<bool, CommitError> {
    if terminal_attempt.len() != 16 || encoded.is_empty() || !encoded.len().is_multiple_of(98) {
        return Ok(false);
    }
    let mut has_terminal = false;
    for source in encoded.chunks_exact(98) {
        let dispatch = &source[..16];
        let sequence = i64::from_be_bytes(
            source[16..24]
                .try_into()
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        );
        let event_kind = source[24];
        let terminal = source[25] == 1;
        let found: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_stream_journal j
                 WHERE j.dispatch_attempt_id=?1 AND j.sequence=?2 AND j.event_kind=?3
                   AND j.terminal=?4 AND j.plaintext_digest=?5 AND j.profile_digest=?6
                   AND j.runtime_generation=?7)",
                params![
                    dispatch,
                    sequence,
                    i64::from(event_kind),
                    i64::from(terminal),
                    &source[26..58],
                    &source[58..90],
                    i64::from_be_bytes(
                        source[90..98]
                            .try_into()
                            .map_err(|_| { storage_failure(StorageFailureKind::CorruptData) })?
                    ),
                ],
                |row| row.get(0),
            )
            .map_err(map_commit_read_error)?;
        if !found {
            return Ok(false);
        }
        if dispatch == terminal_attempt && event_kind == 5 && terminal {
            has_terminal = true;
        }
    }
    Ok(has_terminal)
}
