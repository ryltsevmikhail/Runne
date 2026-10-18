type SpentProofRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

#[expect(
    clippy::too_many_arguments,
    reason = "the predicate checks a single exact stop row against its event, local proof, and bound identities"
)]
fn policy_stop_proven(
    tx: &Connection,
    taskrun_id: TaskRunId,
    attempt: AttemptId,
    area: &[u8],
    command_digest: &[u8],
    state: &str,
    version: i64,
    event_id: EventId,
    event: &TaskRunEvent,
    local: &LocalEffectsProofRow,
) -> Result<bool, EventStoreError> {
    if state != "cancelled"
        || local.state != "cancelled"
        || local.exit_code.is_none()
        || command_digest.len() != 32
        || !matches!(event, TaskRunEvent::TaskRunFailed { reason } if reason == "local_command_policy_stopped_v1")
    {
        return Ok(false);
    }
    type BindingRow = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
    );
    let binding: Option<BindingRow> = tx
        .query_row(
            "SELECT b.fence,b.invocation_id,b.binding_digest,b.binding,b.native_owner_id,
                    b.native_owner_generation,r.route,r.provenance,r.cutover_version
             FROM x2_permission_bindings b JOIN taskrun_local_permission_routes r USING(taskrun_id)
             WHERE b.taskrun_id=?1 AND b.attempt_id=?2",
            rusqlite::params![taskrun_id.as_bytes(), attempt.as_bytes()],
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
                ))
            },
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((fence, invocation, digest, bytes, owner, generation, route, provenance, cutover)) =
        binding
    else {
        return Ok(false);
    };
    let capture =
        super::permission::codec::decode(&bytes).map_err(|_| EventStoreError::CorruptData)?;
    let node = uuid::Uuid::parse_str(&capture.node_id).map_err(|_| EventStoreError::CorruptData)?;
    if !super::permission::codec::digest_matches(&bytes, &digest)
        || route != 2
        || provenance != 3
        || cutover != 68
        || fence <= 0
        || fence != local.fence
        || digest.len() != 32
        || invocation.as_slice() != capture.invocation_id.as_slice()
        || owner.as_slice() != capture.native_owner_id.as_slice()
        || generation.as_slice() != capture.native_owner_generation.to_be_bytes().as_slice()
        || capture.taskrun_id != *taskrun_id.as_bytes()
        || capture.attempt_id != *attempt.as_bytes()
        || capture.fence != fence as u64
        || capture.node_epoch != local.node_epoch as u64
        || node.to_string() != capture.node_id
        || node.as_bytes().as_slice() != local.node_id.as_slice()
        || capture.command_digest.as_slice() != command_digest
        || local.area_identity.as_slice() != area
    {
        return Ok(false);
    }
    let stop = super::permission::stop::stop_reason(
        tx,
        taskrun_id.as_bytes(),
        attempt.as_bytes(),
        &digest,
    )?;
    if !policy_stop_reason_matches(stop, event) {
        return Ok(false);
    }
    super::permission::stop::validate_duplicate_terminal(
        tx,
        taskrun_id.as_bytes(),
        attempt.as_bytes(),
        &digest,
        event,
    )?;
    let settled: bool = tx
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM taskrun_terminal_settlement_receipts r
               JOIN taskrun_assignments a ON a.taskrun_id=r.taskrun_id AND a.fence=r.fence
               JOIN taskrun_claim_receipts c ON c.taskrun_id=a.taskrun_id AND c.fence=a.fence
               JOIN taskrun_assignment_occupations o ON o.taskrun_id=r.taskrun_id AND o.fence=r.fence
               WHERE r.taskrun_id=?1 AND r.attempt_id=?2 AND r.node_id=?3
                 AND r.node_epoch=?4 AND r.fence=?5 AND r.terminal_event_id=?6
                 AND r.terminal_version=?7 AND a.attempt_id=r.attempt_id
                 AND a.node_id=r.node_id AND a.node_epoch=r.node_epoch
                 AND c.attempt_id=a.attempt_id AND c.node_id=a.node_id
                 AND c.node_epoch=a.node_epoch AND c.new_version=4
                 AND o.attempt_id=a.attempt_id AND o.node_id=a.node_id
                 AND o.node_epoch=a.node_epoch AND o.dispatch_intent='absent'
                 AND o.state='released' AND o.release_event_id=r.terminal_event_id
             )",
            rusqlite::params![
                taskrun_id.as_bytes(),
                attempt.as_bytes(),
                &local.node_id,
                local.node_epoch,
                local.fence,
                event_id.as_bytes(),
                version,
            ],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    if !settled {
        return Ok(false);
    }
    type TerminalRow = (
        Vec<u8>,
        i64,
        i64,
        Option<i64>,
        Option<i64>,
        i64,
        i64,
        i64,
        Vec<u8>,
        i64,
        i64,
    );
    let terminal: Option<TerminalRow> = tx
        .query_row(
            "SELECT binding_digest,terminal_kind,exit_kind,exit_code,signal,stdout_eof,
                    stderr_eof,area_empty,event_id,fence,terminal_version
             FROM x2_permission_terminal WHERE taskrun_id=?1 AND attempt_id=?2",
            rusqlite::params![taskrun_id.as_bytes(), attempt.as_bytes()],
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
                    row.get(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((
        saved,
        kind,
        exit_kind,
        code,
        signal,
        stdout_eof,
        stderr_eof,
        empty,
        saved_event,
        saved_fence,
        saved_version,
    )) = terminal
    else {
        return Ok(false);
    };
    let exit_matches = match (exit_kind, code, signal) {
        (1, Some(code), None) if (0..=255).contains(&code) => {
            i32::try_from(code).ok() == local.exit_code
        }
        (2, None, Some(signal @ 1..=64)) => i32::try_from(128 + signal).ok() == local.exit_code,
        _ => false,
    };
    if saved.as_slice() != digest.as_slice()
        || kind != 1
        || stdout_eof != 1
        || stderr_eof != 1
        || empty != 1
        || saved_event.as_slice() != event_id.as_bytes()
        || saved_fence != fence
        || saved_version != version
        || !exit_matches
    {
        return Ok(false);
    }
    let spent: Option<SpentProofRow> = tx
        .query_row(
            "SELECT binding_digest,invocation_id,area_identity,owner_id,owner_generation
             FROM x2_permission_spent WHERE taskrun_id=?1 AND attempt_id=?2",
            rusqlite::params![taskrun_id.as_bytes(), attempt.as_bytes()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    Ok(spent.is_some_and(
        |(saved_digest, saved_invocation, saved_area, saved_owner, saved_gen)| {
            saved_digest.as_slice() == digest.as_slice()
                && saved_invocation.as_slice() == invocation.as_slice()
                && saved_area.as_slice() == area
                && saved_owner.as_slice() == owner.as_slice()
                && saved_gen.as_slice() == generation.as_slice()
        },
    ))
}

fn policy_stop_reason_matches(reason: Option<u8>, event: &TaskRunEvent) -> bool {
    matches!(reason, Some(2..=5))
        && matches!(event, TaskRunEvent::TaskRunFailed { reason } if reason == "local_command_policy_stopped_v1")
}

#[cfg(test)]
include!("effects_policy_stop_tests.rs");
