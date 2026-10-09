use super::{
    model::{load_capture, observation_matches, validate_area},
    terminal::PermissionTerminalCommitV1,
    terminal::PermissionTerminalDuplicateFacts,
    terminal::PermissionTerminalProof,
};
use runne_application::ports::{CommandCommit, CommitError};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;
use rusqlite::{OptionalExtension, Transaction, params};

pub(crate) fn verify_duplicate_rows(
    tx: &Transaction<'_>,
    terminal: &PermissionTerminalCommitV1<'_, '_>,
    payload: &CommandCommit,
) -> Result<PermissionTerminalDuplicateFacts, CommitError> {
    let invalid = super::terminal::terminal_integrity_error;
    let identity = terminal.identity;
    let binding = terminal.binding;
    if identity != binding.assignment()
        || terminal.child.original_binding() != binding
        || !terminal.child.was_released()
        || payload.events.len() != 1
    {
        return Err(invalid());
    }
    let route: Option<(i64, i64, i64)> = tx
        .query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes
             WHERE taskrun_id=?1",
            [identity.taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| invalid())?;
    if route != Some((2, 3, 68)) {
        return Err(invalid());
    }
    let capture = load_capture(tx, identity, binding, true).map_err(|_| invalid())?;
    let digest: [u8; 32] = capture.0.as_slice().try_into().map_err(|_| invalid())?;
    let observation = terminal.child.observation();
    if !observation_matches(binding, observation)
        || observation.owner_id().as_slice() != capture.2.as_slice()
        || observation.owner_generation().to_be_bytes().as_slice() != capture.3.as_slice()
    {
        return Err(invalid());
    }
    super::stop::validate_duplicate_terminal(
        tx,
        identity.taskrun_id.as_bytes(),
        identity.attempt_id.as_bytes(),
        &digest,
        payload.events[0].payload(),
    )
    .map_err(|_| invalid())?;
    let evidence = terminal.child.terminal_evidence().map_err(|_| invalid())?;
    evidence.revalidate_empty_area().map_err(|_| invalid())?;
    if !evidence.output_matches(
        &terminal.output.stdout,
        &terminal.output.stderr,
        terminal.output.stdout_observed,
        terminal.output.stderr_observed,
        terminal.output.stdout_truncated,
        terminal.output.stderr_truncated,
        true,
        true,
        false,
    ) {
        return Err(invalid());
    }
    let area = *evidence.area_identity();
    validate_area(identity, &area).map_err(|_| invalid())?;
    type SpentRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let spent: Option<SpentRow> = tx
        .query_row(
            "SELECT binding_digest,invocation_id,area_identity,owner_id,owner_generation
             FROM x2_permission_spent WHERE taskrun_id=?1 AND attempt_id=?2",
            params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes()
            ],
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
        .map_err(|_| invalid())?;
    if !spent.is_some_and(|r| {
        r.0.as_slice() == digest.as_slice()
            && r.1.as_slice() == binding.invocation_id().as_bytes()
            && r.2.as_slice() == area.as_slice()
            && r.3.as_slice() == capture.2.as_slice()
            && r.4.as_slice() == capture.3.as_slice()
    }) {
        return Err(invalid());
    }
    let (exit_kind, exit_code, signal, legacy_exit_code) = match evidence.leader_exit_kind() {
        LinuxLeaderExitKindV1::Exited { code } => {
            (1_i64, Some(i64::from(code)), None, i32::from(code))
        }
        LinuxLeaderExitKindV1::Signaled { signal, .. } if (1..=64).contains(&signal) => {
            (2, None, Some(i64::from(signal)), 128 + signal)
        }
        LinuxLeaderExitKindV1::Signaled { .. } => return Err(invalid()),
    };
    let event = &payload.events[0];
    let version = payload
        .expected_version
        .checked_add(1)
        .ok_or_else(invalid)?;
    type TerminalRow = (
        Vec<u8>,
        i64,
        i64,
        Option<i64>,
        Option<i64>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        Vec<u8>,
        i64,
        i64,
    );
    let row: Option<TerminalRow> = tx
        .query_row(
            "SELECT binding_digest,terminal_kind,exit_kind,exit_code,signal,stdout,stderr,
                    stdout_observed,stderr_observed,stdout_eof,stderr_eof,stdout_truncated,
                    stderr_truncated,area_empty,event_id,fence,terminal_version
             FROM x2_permission_terminal WHERE taskrun_id=?1 AND attempt_id=?2",
            params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes()
            ],
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
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                ))
            },
        )
        .optional()
        .map_err(|_| invalid())?;
    if !row.is_some_and(|r| {
        r.0.as_slice() == digest.as_slice()
            && r.1 == 1
            && r.2 == exit_kind
            && r.3 == exit_code
            && r.4 == signal
            && r.5 == terminal.output.stdout
            && r.6 == terminal.output.stderr
            && r.7 == terminal.output.stdout_observed
            && r.8 == terminal.output.stderr_observed
            && r.9 == 1
            && r.10 == 1
            && r.11
                == if terminal.output.stdout_truncated {
                    1
                } else {
                    0
                }
            && r.12
                == if terminal.output.stderr_truncated {
                    1
                } else {
                    0
                }
            && r.13 == 1
            && r.14.as_slice() == event.event_id().as_bytes()
            && r.15 == identity.fence.0 as i64
            && r.16 == version as i64
    }) {
        return Err(invalid());
    }
    let attempt: Option<(String, Option<i32>, Vec<u8>)> = tx
        .query_row(
            "SELECT state,exit_code,managed_area_identity FROM taskrun_local_command_attempts
             WHERE taskrun_id=?1 AND attempt_id=?2 AND node_epoch=?3 AND fence=?4",
            params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes(),
                identity.node_epoch as i64,
                identity.fence.0 as i64,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| invalid())?;
    let policy_stopped = matches!(
        event.payload(),
        runne_domain::task_run::TaskRunEvent::TaskRunFailed { reason }
            if reason.as_str() == "local_command_policy_stopped_v1"
    );
    let expected_state = if matches!(
        event.payload(),
        runne_domain::task_run::TaskRunEvent::CancellationCompleted
    ) || policy_stopped
    {
        "cancelled"
    } else {
        "completed"
    };
    if !attempt.is_some_and(|(state, code, stored_area)| {
        state == expected_state && code == Some(legacy_exit_code) && stored_area.as_slice() == area
    }) {
        return Err(invalid());
    }
    Ok(PermissionTerminalDuplicateFacts {
        binding_digest: digest,
        area_identity: area,
        exit_kind: evidence.leader_exit_kind(),
        legacy_exit_code,
        terminal_version: version,
    })
}

pub(crate) fn settle_and_record(
    tx: &Transaction<'_>,
    terminal: &PermissionTerminalCommitV1<'_, '_>,
    proof: &PermissionTerminalProof,
    now: i64,
) -> Result<(), CommitError> {
    let invalid = super::terminal::terminal_integrity_error;
    let evidence = terminal.child.terminal_evidence().map_err(|_| invalid())?;
    evidence.revalidate_empty_area().map_err(|_| invalid())?;
    if evidence.area_identity().as_slice() != proof.area_identity.as_slice()
        || evidence.leader_exit_kind() != proof.exit_kind
    {
        return Err(invalid());
    }
    crate::store::taskrun_local_command::settlement::settle(
        tx,
        terminal.identity,
        &proof.area_identity,
        proof.event_id,
        proof.terminal_version,
    )
    .map_err(|_| invalid())?;
    let (exit_kind, exit_code, signal) = match proof.exit_kind {
        LinuxLeaderExitKindV1::Exited { code } => (1_i64, Some(i64::from(code)), None),
        LinuxLeaderExitKindV1::Signaled { signal, .. } => (2, None, Some(i64::from(signal))),
    };
    let changed = tx
        .execute(
            "INSERT INTO x2_permission_terminal(
               taskrun_id,attempt_id,binding_digest,terminal_kind,exit_kind,exit_code,signal,
               stdout,stderr,stdout_observed,stderr_observed,stdout_eof,stderr_eof,
               stdout_truncated,stderr_truncated,area_empty,event_id,fence,terminal_version,settled_at
             ) VALUES (?1,?2,?3,1,?4,?5,?6,?7,?8,?9,?10,1,1,?11,?12,1,?13,?14,?15,?16)",
            params![
                terminal.identity.taskrun_id.as_bytes(),
                terminal.identity.attempt_id.as_bytes(),
                proof.binding_digest.as_slice(),
                exit_kind,
                exit_code,
                signal,
                terminal.output.stdout,
                terminal.output.stderr,
                terminal.output.stdout_observed,
                terminal.output.stderr_observed,
                if terminal.output.stdout_truncated { 1_i64 } else { 0_i64 },
                if terminal.output.stderr_truncated { 1_i64 } else { 0_i64 },
                proof.event_id.as_bytes(),
                terminal.identity.fence.0 as i64,
                proof.terminal_version as i64,
                now.max(1),
            ],
        )
        .map_err(|_| invalid())?;
    if changed != 1 {
        return Err(invalid());
    }
    Ok(())
}
