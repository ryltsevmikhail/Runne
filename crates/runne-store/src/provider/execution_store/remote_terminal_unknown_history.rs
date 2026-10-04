use runne_domain::conversation::ConversationEvent;

type UnknownOriginalHistoryFacts = ([u8; 32], [u8; 32], Option<[u8; 32]>, [u8; 32], [u8; 32], u64, u64);
type UnknownTaskRunClaimRow = (Vec<u8>, i64, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>);

fn load_unknown_original_history(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    conversation_id: ConversationId,
    principal_id: &str,
    _: &ExecutionAttempt,
) -> Result<UnknownOriginalHistoryFacts, ProviderExecutionError> {
    let taskrun = crate::store::test_support_diagnostics::on_error(
        "unknown.taskrun_stream",
        crate::store::taskrun_claim::stream_validate::verify_stream(connection, taskrun_id, None)
            .map_err(|_| ProviderExecutionError::JournalCorrupt),
    )?;
    if let Some(origin) = crate::store::test_support_diagnostics::on_error(
        "unknown.submit_origin",
        crate::store::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
            connection, taskrun_id,
        )
        .map_err(|_| ProviderExecutionError::JournalCorrupt),
    )?
        && (origin.conversation_id != conversation_id || origin.principal_id.0 != principal_id) {
            return Err(ProviderExecutionError::TerminalConflict);
        }
    let started_index = taskrun
        .events
        .iter()
        .position(|event| {
            matches!(event.payload(),
            runne_domain::task_run::TaskRunEvent::AttemptStarted { attempt_id: started }
                if *started == attempt_id)
        })
        .ok_or_else(|| {
            crate::store::test_support_diagnostics::record("unknown.started_event_missing");
            ProviderExecutionError::JournalCorrupt
        })?;
    if taskrun
        .events
        .iter()
        .filter(|event| {
            matches!(event.payload(),
        runne_domain::task_run::TaskRunEvent::AttemptStarted { attempt_id: started }
            if *started == attempt_id)
        })
        .count()
        != 1
    {
        crate::store::test_support_diagnostics::record("unknown.started_event_count");
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    for event in &taskrun.events {
        if let runne_domain::task_run::TaskRunEvent::TaskRunSubmitted {
            conversation_id: submitted,
            ..
        } = event.payload()
            && *submitted != conversation_id
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
    }
    let started = &taskrun.events[started_index];
    let taskrun_history = unknown_event_prefix_digest(&taskrun.events[..=started_index]);
    let conversation = crate::store::test_support_diagnostics::on_error(
        "unknown.conversation_stream",
        crate::store::load_conversation_from_connection(connection, conversation_id)
            .map_err(|_| ProviderExecutionError::JournalCorrupt),
    )?;
    let workspace_id = match conversation.events.first().map(|event| event.payload()) {
        Some(runne_domain::conversation::ConversationEvent::ConversationCreated {
            workspace_id,
        }) => *workspace_id,
        _ => {
            crate::store::test_support_diagnostics::record("unknown.conversation_origin");
            return Err(ProviderExecutionError::JournalCorrupt);
        }
    };
    let matching_messages: Vec<_> = conversation.events.iter().enumerate().filter(|(_, event)| {
        matches!(event.payload(), runne_domain::conversation::ConversationEvent::UserMessageAppended {
            taskrun_id: owner, attempt_id: active, ..
        } if *owner == taskrun_id && *active == attempt_id)
    }).collect();
    if matching_messages.len() != 1 {
        crate::store::test_support_diagnostics::record("unknown.begin_message_count");
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let (message_index, begin) = matching_messages[0];
    let ConversationEvent::UserMessageAppended {
        message_id,
        text,
        taskrun_id: owner,
        attempt_id: active,
    } = begin.payload()
    else {
        return Err(ProviderExecutionError::JournalCorrupt);
    };
    if *owner != taskrun_id || *active != attempt_id {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let begin_receipt = crate::store::test_support_diagnostics::on_error(
        "unknown.begin_receipt",
        verify_unknown_begin_receipt(
            connection,
            UnknownBeginReceiptExpectation {
                conversation_id,
                taskrun_id,
                attempt_id,
                message_id: *message_id,
                text,
                event: begin,
                taskrun_version: started.sequence(),
                expected_principal: principal_id,
                workspace_id,
            },
        ),
    )?;
    let claims: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND attempt_id=?2",
            params![
                taskrun_id.as_bytes().as_slice(),
                attempt_id.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if claims > 1 {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    if claims == 0 {
        let assignment_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM taskrun_assignments WHERE taskrun_id=?1",
                [taskrun_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
        let direct_prefix = taskrun.events.get(..4).is_some_and(|events| {
            matches!(events[0].payload(), runne_domain::task_run::TaskRunEvent::TaskRunCreated)
                && matches!(events[1].payload(), runne_domain::task_run::TaskRunEvent::TaskRunQueued)
                && matches!(events[2].payload(), runne_domain::task_run::TaskRunEvent::TaskRunAdmitted)
                && matches!(events[3].payload(), runne_domain::task_run::TaskRunEvent::AttemptStarted { attempt_id: started } if *started == attempt_id)
        });
        if assignment_count != 0 || !direct_prefix || started_index != 3 {
            return Err(ProviderExecutionError::TerminalConflict);
        }
    }
    let claim = if claims == 1 {
        let row: UnknownTaskRunClaimRow = connection
            .query_row(
                "SELECT node_id,node_epoch,fence, new_version, admitted_event_id, started_event_id, command_id
                 FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND attempt_id=?2",
                params![taskrun_id.as_bytes().as_slice(), attempt_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
            )
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
        let started_event = unknown_fixed_bytes::<16>(row.5.clone())?;
        let node_id = unknown_fixed_bytes::<16>(row.0.clone())?;
        if started_event != *started.event_id().as_bytes()
            || unknown_positive_u64(row.3)? != started.sequence()
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let identity = runne_application::ports::TaskRunAssignmentIdentity {
            taskrun_id,
            attempt_id,
            node_id: runne_application::ports::ExecutionNodeId(
                uuid::Uuid::from_bytes(node_id).to_string(),
            ),
            node_epoch: unknown_positive_u64(row.1)?,
            fence: runne_application::ports::TaskRunFence(unknown_positive_u64(row.2)?),
        };
        crate::store::test_support_diagnostics::on_error(
            "unknown.assignment_history",
            crate::store::taskrun_claim::verify_assignment_history(connection, &identity)
                .map_err(|_| ProviderExecutionError::JournalCorrupt),
        )?;
        let mut hash = Sha256::new();
        hash.update(b"GOCODE_PROVIDER_UNKNOWN_CLAIM_RECEIPT_V1\0");
        for value in [&row.0, &row.4, &row.5, &row.6] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        for value in [row.1, row.2, row.3] {
            hash.update(value.to_be_bytes());
        }
        Some(<[u8; 32]>::from(hash.finalize()))
    } else {
        None
    };
    let conversation_history = unknown_event_prefix_digest(&conversation.events[..=message_index]);
    Ok((
        begin_receipt,
        *started.integrity_digest().as_bytes(),
        claim,
        taskrun_history,
        conversation_history,
        started.sequence(),
        begin.sequence(),
    ))
}

fn unknown_event_prefix_digest<E>(events: &[runne_domain::event::EventEnvelope<E>]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"GOCODE_PROVIDER_UNKNOWN_EVENT_PREFIX_V1\0");
    digest.update((events.len() as u64).to_be_bytes());
    for event in events {
        digest.update(event.sequence().to_be_bytes());
        digest.update(event.event_id().as_bytes());
        digest.update(event.integrity_digest().as_bytes());
    }
    digest.finalize().into()
}
