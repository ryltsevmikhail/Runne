struct LocalStopRow {
    attempt_id: Vec<u8>,
    historic_node_id: Vec<u8>,
    historic_node_epoch: i64,
    proof_node_id: Vec<u8>,
    proof_node_epoch: i64,
    area_identity: Vec<u8>,
    command_digest: Vec<u8>,
    terminal_event_id: Vec<u8>,
    terminal_version: i64,
}

struct LocalAttemptRow {
    conversation_id: Vec<u8>,
    workspace_id: Vec<u8>,
    command_digest: Vec<u8>,
    attempt_id: Option<Vec<u8>>,
    node_id: Option<Vec<u8>>,
    node_epoch: Option<i64>,
    fence: Option<i64>,
    area_identity: Option<Vec<u8>>,
    state: String,
    exit_code: Option<i64>,
}

pub(super) fn local_stop_receipts_match(connection: &Connection) -> SqliteResult<bool> {
    let mut statement = connection.prepare(
        "SELECT taskrun_id,attempt_id,historic_node_id,historic_node_epoch,fence,
                terminal_event_id,terminal_version
         FROM taskrun_local_command_stop_receipts ORDER BY taskrun_id,fence",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, i64>(6)?,
        ))
    })?;
    for row in rows {
        let (task, attempt, node, epoch, fence, terminal_id, version) = row?;
        let event: Option<Vec<u8>> = connection
            .query_row(
                "SELECT payload FROM events WHERE event_id=?1 AND aggregate_type=1 AND aggregate_id=?2 AND sequence=?3",
                rusqlite::params![terminal_id, task, version],
                |row| row.get(0),
            )
            .optional()?;
        let Some(payload) = event else {
            return Ok(false);
        };
        let Ok(runne_domain::task_run::TaskRunEvent::Unrecoverable) =
            TaskRunEventCodec.decode(&payload)
        else {
            return Ok(false);
        };
        if !local_stop_terminal_proof_matches(
            connection,
            &task,
            &attempt,
            &node,
            epoch,
            fence,
            &runne_domain::task_run::TaskRunEvent::Unrecoverable,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn local_stop_terminal_proof_matches(
    connection: &Connection,
    taskrun_id: &[u8],
    attempt_id: &[u8],
    node_id: &[u8],
    node_epoch: i64,
    fence: i64,
    event: &runne_domain::task_run::TaskRunEvent,
) -> SqliteResult<bool> {
    if !matches!(event, runne_domain::task_run::TaskRunEvent::Unrecoverable) {
        return Ok(false);
    }
    let row = connection
        .query_row(
            "SELECT attempt_id,historic_node_id,historic_node_epoch,proof_node_id,
                    proof_node_epoch,managed_area_identity,command_digest,
                    terminal_event_id,terminal_version
             FROM taskrun_local_command_stop_receipts WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id, fence],
            |row| {
                Ok(LocalStopRow {
                    attempt_id: row.get(0)?,
                    historic_node_id: row.get(1)?,
                    historic_node_epoch: row.get(2)?,
                    proof_node_id: row.get(3)?,
                    proof_node_epoch: row.get(4)?,
                    area_identity: row.get(5)?,
                    command_digest: row.get(6)?,
                    terminal_event_id: row.get(7)?,
                    terminal_version: row.get(8)?,
                })
            },
        )
        .optional()?;
    let Some(receipt) = row else {
        return Ok(false);
    };
    if receipt.attempt_id != attempt_id
        || receipt.historic_node_id != node_id
        || receipt.historic_node_epoch != node_epoch
        || receipt.proof_node_id != node_id
        || receipt.proof_node_epoch <= node_epoch
        || receipt.terminal_version < 6
        || !local_area_identity_matches(&receipt.area_identity, taskrun_id, attempt_id)
    {
        return Ok(false);
    }
    let taskrun_bytes = match <[u8; 16]>::try_from(taskrun_id) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false),
    };
    let origin = match crate::store::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
        connection,
        runne_domain::id::TaskRunId::from_bytes(taskrun_bytes),
    ) {
        Ok(Some(origin)) => origin,
        Ok(None) | Err(_) => return Ok(false),
    };
    let Some(command) = origin.input.local_command() else {
        return Ok(false);
    };
    let local = connection
        .query_row(
            "SELECT conversation_id,workspace_id,command_digest,attempt_id,node_id,node_epoch,
                    fence,managed_area_identity,state,exit_code
             FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id],
            |row| {
                Ok(LocalAttemptRow {
                    conversation_id: row.get(0)?,
                    workspace_id: row.get(1)?,
                    command_digest: row.get(2)?,
                    attempt_id: row.get(3)?,
                    node_id: row.get(4)?,
                    node_epoch: row.get(5)?,
                    fence: row.get(6)?,
                    area_identity: row.get(7)?,
                    state: row.get(8)?,
                    exit_code: row.get(9)?,
                })
            },
        )
        .optional()?;
    let Some(local) = local else {
        return Ok(false);
    };
    if command.intent_digest().as_slice() != receipt.command_digest
        || local.conversation_id != origin.conversation_id.as_bytes()
        || local.workspace_id != origin.workspace_id.as_bytes()
        || local.command_digest != receipt.command_digest
        || local.attempt_id.as_deref() != Some(attempt_id)
        || local.node_id.as_deref() != Some(node_id)
        || local.node_epoch != Some(node_epoch)
        || local.fence != Some(fence)
        || local.area_identity.as_deref() != Some(receipt.area_identity.as_slice())
        || local.state != "outcome_unknown"
        || local.exit_code.is_some()
    {
        return Ok(false);
    }
    let valid: bool = connection.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM taskrun_local_command_stop_receipts r
           JOIN taskrun_assignments a ON a.taskrun_id=r.taskrun_id AND a.fence=r.fence
           JOIN taskrun_claim_receipts c ON c.taskrun_id=a.taskrun_id AND c.fence=a.fence
           JOIN taskrun_assignment_occupations o ON o.taskrun_id=a.taskrun_id AND o.fence=a.fence
           JOIN taskrun_terminal_settlement_receipts t ON t.taskrun_id=r.taskrun_id AND t.fence=r.fence
           JOIN events terminal ON terminal.event_id=r.terminal_event_id
           JOIN aggregate_streams stream ON stream.aggregate_type=1 AND stream.aggregate_id=r.taskrun_id
           JOIN events reconcile ON reconcile.aggregate_type=1 AND reconcile.aggregate_id=r.taskrun_id
                AND reconcile.sequence=r.terminal_version-1
           JOIN events prior ON prior.aggregate_type=1 AND prior.aggregate_id=r.taskrun_id
                AND prior.sequence=r.terminal_version-2
           JOIN events started ON started.aggregate_type=1 AND started.aggregate_id=r.taskrun_id
                AND started.sequence=4
           WHERE r.taskrun_id=?1 AND r.fence=?2 AND r.attempt_id=?3
             AND r.historic_node_id=?4 AND r.historic_node_epoch=?5
             AND r.proof_node_id=?4 AND r.proof_node_epoch>?5
             AND r.stop_kind='outcome_unknown' AND r.terminal_event_id=?6
             AND r.terminal_version=?7 AND r.command_digest=?8
             AND a.attempt_id=r.attempt_id AND a.node_id=r.historic_node_id
             AND a.node_epoch=r.historic_node_epoch
             AND c.attempt_id=a.attempt_id AND c.node_id=a.node_id
             AND c.node_epoch=a.node_epoch AND c.new_version=4
             AND c.started_event_id=started.event_id
             AND o.attempt_id=a.attempt_id AND o.node_id=a.node_id
             AND o.node_epoch=a.node_epoch AND o.dispatch_intent='absent'
             AND o.state='released' AND o.release_event_id=r.terminal_event_id
             AND t.attempt_id=a.attempt_id AND t.node_id=a.node_id
             AND t.node_epoch=a.node_epoch AND t.terminal_event_id=r.terminal_event_id
             AND t.terminal_version=r.terminal_version
             AND terminal.sequence=r.terminal_version
             AND terminal.aggregate_type=1 AND terminal.aggregate_id=r.taskrun_id
             AND terminal.causation_id=reconcile.event_id
             AND stream.current_version=r.terminal_version
             AND stream.last_event_id=r.terminal_event_id
             AND reconcile.causation_id=prior.event_id
             AND reconcile.command_id=terminal.command_id
             AND reconcile.command_id!=zeroblob(16)
             AND reconcile.idempotency_key=terminal.idempotency_key
             AND reconcile.actor=terminal.actor
             AND reconcile.actor=x'73797374656d3a6c6f63616c5f636f6d6d616e645f7265636f76657279'
             AND reconcile.idempotency_key=?9
             AND length(reconcile.command_id)=16
         )",
        rusqlite::params![
            taskrun_id,
            fence,
            attempt_id,
            node_id,
            node_epoch,
            receipt.terminal_event_id,
            receipt.terminal_version,
            receipt.command_digest,
            format!(
                "local-command-recovery-unknown-v1:{}:{fence}:{}",
                uuid::Uuid::from_bytes(taskrun_bytes),
                receipt.proof_node_epoch
            )
            .into_bytes(),
        ],
        |row| row.get(0),
    )?;
    if !valid {
        return Ok(false);
    }
    let reconcile_payload: Vec<u8> = connection.query_row(
        "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2",
        rusqlite::params![taskrun_id, receipt.terminal_version - 1],
        |row| row.get(0),
    )?;
    if !matches!(
        TaskRunEventCodec.decode(&reconcile_payload),
        Ok(runne_domain::task_run::TaskRunEvent::ReconciliationStarted)
    ) {
        return Ok(false);
    }
    let started_payload: Vec<u8> = connection.query_row(
        "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=4",
        [taskrun_id],
        |row| row.get(0),
    )?;
    Ok(matches!(
        TaskRunEventCodec.decode(&started_payload),
        Ok(runne_domain::task_run::TaskRunEvent::AttemptStarted { attempt_id: started })
            if started.as_bytes() == attempt_id
    ))
}
