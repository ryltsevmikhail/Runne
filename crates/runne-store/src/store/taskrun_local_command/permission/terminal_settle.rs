use super::terminal::{PermissionTerminalCommitV1, PermissionTerminalProof};
use runne_application::ports::CommitError;
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;
use rusqlite::{Transaction, params};

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
