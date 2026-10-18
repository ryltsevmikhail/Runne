use super::terminal::{PermissionTerminalCommitV1, PermissionTerminalProof};
use runne_application::ports::CommitError;
use rusqlite::{OptionalExtension, Transaction, params};

/// Validates and applies the attempt-row transition of the V68 terminal UoW.
///
/// Row parity with the legacy settlement: a durably recorded factual exit
/// (`completed` + exact leader code) stays authoritative for both terminal
/// outcomes — a cancellation racing that record keeps state and exit untouched
/// (legacy `confirm_local_command_stopped`), while a fresh `running` row is
/// transitioned here with the observed flat leader code.
pub(crate) fn prepare(
    tx: &Transaction<'_>,
    terminal: &PermissionTerminalCommitV1<'_, '_>,
    proof: &PermissionTerminalProof,
) -> Result<(), CommitError> {
    let invalid = super::terminal::terminal_integrity_error;
    let capture = super::model::load_capture(tx, terminal.identity, terminal.binding, false)
        .or_else(|_| super::model::load_capture(tx, terminal.identity, terminal.binding, true))
        .map_err(|_| invalid())?;
    if capture.0.as_slice() != proof.binding_digest.as_slice() {
        return Err(invalid());
    }
    let evidence = terminal.child.terminal_evidence().map_err(|_| invalid())?;
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
    let row: Option<(String, Option<i32>, Vec<u8>)> = tx
        .query_row(
            "SELECT state,exit_code,managed_area_identity FROM taskrun_local_command_attempts
             WHERE taskrun_id=?1 AND attempt_id=?2 AND node_epoch=?3 AND fence=?4",
            params![
                terminal.identity.taskrun_id.as_bytes(),
                terminal.identity.attempt_id.as_bytes(),
                terminal.identity.node_epoch as i64,
                terminal.identity.fence.0 as i64,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| invalid())?;
    let factual_exit_recorded = row.as_ref().is_some_and(|(state, code, area)| {
        state == "completed"
            && *code == Some(proof.legacy_exit_code)
            && area.as_slice() == proof.area_identity.as_slice()
    });
    if !factual_exit_recorded
        && !row.as_ref().is_some_and(|(state, code, area)| {
            state == "running"
                && code.is_none()
                && area.as_slice() == proof.area_identity.as_slice()
        })
    {
        return Err(invalid());
    }
    if !factual_exit_recorded {
        transition_running_row(tx, terminal, proof)?;
    }
    super::model::load_capture(tx, terminal.identity, terminal.binding, true)
        .map_err(|_| invalid())?;
    Ok(())
}

fn transition_running_row(
    tx: &Transaction<'_>,
    terminal: &PermissionTerminalCommitV1<'_, '_>,
    proof: &PermissionTerminalProof,
) -> Result<(), CommitError> {
    let invalid = super::terminal::terminal_integrity_error;
    let identity = terminal.identity;
    let taskrun = identity.taskrun_id.as_bytes();
    let attempt = identity.attempt_id.as_bytes();
    let epoch = identity.node_epoch as i64;
    let fence = identity.fence.0 as i64;
    let area = proof.area_identity.as_slice();
    let now = super::model::now_ms();
    let changed = if proof.stopped {
        let reserved = tx
            .execute(
                "UPDATE taskrun_local_command_attempts
                 SET state='cancel_requested',exit_code=?1,updated_at=?2
                 WHERE taskrun_id=?3 AND attempt_id=?4 AND node_epoch=?5 AND fence=?6
                   AND managed_area_identity=?7 AND state='running'",
                params![
                    proof.legacy_exit_code,
                    now,
                    taskrun,
                    attempt,
                    epoch,
                    fence,
                    area
                ],
            )
            .map_err(|_| invalid())?;
        if reserved != 1 {
            return Err(invalid());
        }
        tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='cancelled',updated_at=?1
             WHERE taskrun_id=?2 AND attempt_id=?3 AND node_epoch=?4 AND fence=?5
               AND managed_area_identity=?6 AND state='cancel_requested' AND exit_code=?7",
            params![
                now,
                taskrun,
                attempt,
                epoch,
                fence,
                area,
                proof.legacy_exit_code
            ],
        )
        .map_err(|_| invalid())?
    } else {
        tx.execute(
            "UPDATE taskrun_local_command_attempts
             SET state='completed',exit_code=?1,updated_at=?2
             WHERE taskrun_id=?3 AND attempt_id=?4 AND node_epoch=?5 AND fence=?6
               AND managed_area_identity=?7 AND state='running'",
            params![
                proof.legacy_exit_code,
                now,
                taskrun,
                attempt,
                epoch,
                fence,
                area
            ],
        )
        .map_err(|_| invalid())?
    };
    if changed != 1 {
        return Err(invalid());
    }
    Ok(())
}
