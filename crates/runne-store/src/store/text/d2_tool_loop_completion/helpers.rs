use super::*;

pub(super) struct CompletionRow {
    taskrun: Vec<u8>,
    attempt: Vec<u8>,
    cycle: Vec<u8>,
    outbox: Vec<u8>,
    text_digest: Vec<u8>,
    receipt_digest: Vec<u8>,
    terminal_attempt: Vec<u8>,
    terminal_sequence: i64,
    settlement_digest: Vec<u8>,
    evaluation_digest: Vec<u8>,
    taskrun_head: i64,
    message_id: Vec<u8>,
    sources: Vec<u8>,
}
impl CompletionRow {
    pub(super) fn matches_replay(
        &self,
        binding: &crate::store::D2ToolLoopCompletionReplayBinding,
        receipt_digest: IntegrityDigest,
    ) -> bool {
        self.taskrun.as_slice() == binding.taskrun_id.as_bytes()
            && self.attempt.as_slice() == binding.attempt_id.as_bytes()
            && self.cycle.as_slice() == binding.cycle_id.as_bytes()
            && self.outbox.as_slice() == binding.terminal_outbox_id
            && self.text_digest.as_slice() == binding.assistant_text_digest.as_bytes()
            && self.receipt_digest.as_slice() == receipt_digest.as_bytes()
            && self.terminal_attempt.as_slice() == binding.terminal_attempt_id
            && u64::try_from(self.terminal_sequence).ok() == Some(binding.terminal_sequence)
            && self.settlement_digest.as_slice() == binding.settlement_digest.as_bytes()
            && self.evaluation_digest.as_slice()
                == binding.evaluation_ref.evaluation_digest.as_bytes()
            && u64::try_from(self.taskrun_head).ok() == Some(binding.taskrun_head)
            && self.message_id.as_slice() == binding.assistant_message_id.as_bytes()
            && self.sources == encode_terminal_sources(&binding.terminal_sources)
    }

    pub(super) fn matches(
        &self,
        input: &D2ToolLoopCompletionV1,
        message: MessageId,
        digest: IntegrityDigest,
    ) -> bool {
        self.taskrun.as_slice() == input.taskrun_id.as_bytes()
            && self.attempt.as_slice() == input.attempt_id.as_bytes()
            && self.cycle.as_slice() == input.cycle_id.as_bytes()
            && self.outbox.as_slice() == input.terminal_outbox_id
            && self.text_digest.as_slice() == input.assistant_text_digest.as_bytes()
            && self.receipt_digest.as_slice() == digest.as_bytes()
            && self.terminal_attempt.as_slice() == input.terminal_attempt_id
            && self.terminal_sequence == input.terminal_sequence as i64
            && self.settlement_digest.as_slice() == input.settlement_digest.as_bytes()
            && self.evaluation_digest.as_slice()
                == input.evaluation_ref.evaluation_digest.as_bytes()
            && self.taskrun_head == input.expected_taskrun_head as i64
            && self.message_id.as_slice() == message.as_bytes()
            && self.sources == encode_terminal_sources(&input.terminal_sources)
            && message == input.completed_receipt.assistant_message_id
    }
}

pub(super) fn receipt_digest(
    receipt: &TextGenerationReceipt,
) -> Result<IntegrityDigest, CommitError> {
    use crate::store::parse_helpers::storage_failure;
    let encoded = TextGenerationReceiptCodec
        .encode(receipt)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(IntegrityDigest::from_bytes(Sha256::digest(&encoded).into()))
}

pub(super) fn completion_row(
    tx: &rusqlite::Transaction<'_>,
    command: CommandId,
) -> Result<Option<CompletionRow>, CommitError> {
    use crate::store::parse_helpers::storage_failure;
    tx.query_row("SELECT taskrun_id,attempt_id,cycle_id,terminal_outbox_id,assistant_text_digest,completed_receipt_digest,terminal_attempt_id,terminal_sequence,settlement_digest,evaluation_digest,taskrun_head,assistant_message_id,terminal_sources FROM d2_tool_loop_completions WHERE command_id=?1", [command.as_bytes()], |r| Ok(CompletionRow { taskrun:r.get(0)?, attempt:r.get(1)?, cycle:r.get(2)?, outbox:r.get(3)?, text_digest:r.get(4)?, receipt_digest:r.get(5)?,terminal_attempt:r.get(6)?,terminal_sequence:r.get(7)?,settlement_digest:r.get(8)?,evaluation_digest:r.get(9)?,taskrun_head:r.get(10)?,message_id:r.get(11)?,sources:r.get(12)? }))
        .optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}

pub(super) fn validate_terminal_outbox(
    tx: &rusqlite::Transaction<'_>,
    input: &D2ToolLoopCompletionV1,
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    let terminal_sequence = i64::try_from(input.terminal_sequence)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let valid: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM provider_terminal_outbox o JOIN provider_terminal_application_kinds k USING(dispatch_attempt_id,outbox_id) JOIN provider_execution_admissions a USING(dispatch_attempt_id) WHERE o.dispatch_attempt_id=?1 AND o.outbox_id=?2 AND o.terminal_sequence=?3 AND o.settlement_digest=?4 AND o.state=1 AND o.plaintext_digest=?9 AND o.plaintext_len=?10 AND k.application_kind=2 AND a.taskrun_id=?5 AND a.execution_attempt_id=?6 AND a.conversation_id=?7 AND a.principal_id=?8)", params![input.terminal_attempt_id.as_slice(),input.terminal_outbox_id.as_slice(),terminal_sequence,input.settlement_digest.as_bytes(),input.taskrun_id.as_bytes(),input.attempt_id.as_bytes(),input.conversation_id.as_bytes(),input.idempotency_scope.principal_id.0,input.assistant_text_digest.as_bytes(),i64::try_from(input.assistant_text_length).map_err(|_|storage_failure(StorageFailureKind::IntegrityViolation))?], |r| r.get(0)).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !valid {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let dispatch = input.terminal_attempt_id;
    let terminal_valid = input.terminal_sources.len() <= 32
        && input.terminal_sources.last().is_some_and(|source| {
            source.dispatch_attempt_id == dispatch
                && source.sequence == input.terminal_sequence
                && source.event_kind == 5
                && source.terminal
        })
        && input.terminal_sources[..input.terminal_sources.len().saturating_sub(1)]
            .iter()
            .all(|source| {
                source.dispatch_attempt_id == dispatch && source.event_kind == 7 && !source.terminal
            })
        && input
            .terminal_sources
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence);
    if !terminal_valid {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let completed: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_terminal_dispositions WHERE dispatch_attempt_id=?1 AND disposition=1)",
            [dispatch.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !completed {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    for source in &input.terminal_sources {
        let found: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM provider_stream_journal j JOIN provider_execution_admissions a USING(dispatch_attempt_id) WHERE j.dispatch_attempt_id=?1 AND j.sequence=?2 AND j.event_kind=?3 AND j.terminal=?4 AND j.plaintext_digest=?5 AND j.profile_digest=?6 AND j.runtime_generation=?7 AND a.taskrun_id=?8 AND a.execution_attempt_id=?9 AND a.conversation_id=?10 AND a.principal_id=?11)", params![source.dispatch_attempt_id.as_slice(),i64::try_from(source.sequence).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,i64::from(source.event_kind),i64::from(source.terminal),source.plaintext_digest.as_bytes(),source.profile_digest.as_bytes(),i64::try_from(source.runtime_generation).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,input.taskrun_id.as_bytes(),input.attempt_id.as_bytes(),input.conversation_id.as_bytes(),input.idempotency_scope.principal_id.0], |r|r.get(0)).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if !found {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    }
    let outbox_source_matches: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM provider_terminal_outbox o JOIN provider_stream_journal j ON j.dispatch_attempt_id=o.dispatch_attempt_id AND j.sequence=o.terminal_sequence WHERE o.outbox_id=?1 AND j.sequence=?2 AND j.event_kind=?3 AND j.terminal=1 AND j.profile_digest=o.profile_digest AND j.runtime_generation=o.runtime_generation AND j.key_id=o.key_id AND j.key_version=o.key_version)", params![input.terminal_outbox_id.as_slice(), terminal_sequence, 5], |row| row.get(0)).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !outbox_source_matches {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

pub(super) fn retire_d2_occupation(
    tx: &rusqlite::Transaction<'_>,
    input: &D2ToolLoopCompletionV1,
    event: EventId,
    version: u64,
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    let assignment = &input.assignment;
    let node = uuid::Uuid::parse_str(&assignment.node_id.0)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let node_bytes = node.as_bytes();
    let row: Option<(String,Option<Vec<u8>>)> = tx.query_row("SELECT state,release_event_id FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5", params![input.taskrun_id.as_bytes(),assignment.fence.0 as i64,input.attempt_id.as_bytes(),node_bytes,assignment.node_epoch as i64], |r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    match row {
        Some((state, Some(release)))
            if state == "released" && release.as_slice() == event.as_bytes() =>
        {
            let settled: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts
                     WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4
                       AND node_epoch=?5 AND terminal_event_id=?6 AND terminal_version=?7)",
                    params![
                        input.taskrun_id.as_bytes(),
                        assignment.fence.0 as i64,
                        input.attempt_id.as_bytes(),
                        node_bytes,
                        assignment.node_epoch as i64,
                        event.as_bytes(),
                        version as i64,
                    ],
                    |row| row.get(0),
                )
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
            if !settled {
                return Err(storage_failure(StorageFailureKind::IntegrityViolation));
            }
            return Ok(());
        }
        Some((state, None)) if state == "active" => {}
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    }
    tx.execute("INSERT INTO taskrun_terminal_settlement_receipts(taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![input.taskrun_id.as_bytes(),assignment.fence.0 as i64,input.attempt_id.as_bytes(),node_bytes,assignment.node_epoch as i64,event.as_bytes(),version as i64]).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let changed = tx.execute("UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1 WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6 AND state='active' AND release_event_id IS NULL", params![event.as_bytes(),input.taskrun_id.as_bytes(),assignment.fence.0 as i64,input.attempt_id.as_bytes(),node_bytes,assignment.node_epoch as i64]).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if changed != 1 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

pub(super) fn write_completion_linkage(
    tx: &rusqlite::Transaction<'_>,
    input: &D2ToolLoopCompletionV1,
    message: MessageId,
    receipt_digest: IntegrityDigest,
    now: i64,
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    let sources = encode_terminal_sources(&input.terminal_sources);
    tx.execute("INSERT INTO d2_tool_loop_completions(command_id,taskrun_id,attempt_id,cycle_id,taskrun_head,evaluation_digest,terminal_attempt_id,terminal_outbox_id,terminal_sequence,settlement_digest,terminal_sources,assistant_message_id,assistant_text_digest,completed_receipt_digest,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)", params![input.command_id.as_bytes(),input.taskrun_id.as_bytes(),input.attempt_id.as_bytes(),input.cycle_id.as_bytes(),input.expected_taskrun_head as i64,input.evaluation_ref.evaluation_digest.as_bytes(),input.terminal_attempt_id.as_slice(),input.terminal_outbox_id.as_slice(),input.terminal_sequence as i64,input.settlement_digest.as_bytes(),sources,message.as_bytes(),input.assistant_text_digest.as_bytes(),receipt_digest.as_bytes(),now]).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(())
}

pub(super) fn encode_terminal_sources(sources: &[D2ToolTerminalSourceV1]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(sources.len() * 98);
    for source in sources {
        bytes.extend_from_slice(&source.dispatch_attempt_id);
        bytes.extend_from_slice(&source.sequence.to_be_bytes());
        bytes.push(source.event_kind);
        bytes.push(u8::from(source.terminal));
        bytes.extend_from_slice(source.plaintext_digest.as_bytes());
        bytes.extend_from_slice(source.profile_digest.as_bytes());
        bytes.extend_from_slice(&source.runtime_generation.to_be_bytes());
    }
    bytes
}

pub(super) fn message_event_id(event: &UncommittedEvent<ConversationEvent>) -> EventId {
    *event.event_id()
}
