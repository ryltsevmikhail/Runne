/// Strict reopen admission for a V68 CurrentPermission cancellation receipt.
///
/// Unlike the legacy V51 matcher (`local_attempt_terminal_state_matches`),
/// which admits `cancelled` attempts only with a NULL exit, the live
/// permission stop records the leader's factual exit in the attempt row
/// (`128 + signal` for a signalled leader). This matcher therefore admits a
/// `TaskRunCancelled`/`CancellationCompleted` receipt only when every linked
/// row describes one consistent live stop:
///
/// * the receipt's terminal event id/version equal the
///   `x2_permission_terminal` sidecar's own event, on the same fence;
/// * the sidecar is a `terminal_kind=1` (spent) terminal with a factual exit
///   shape (exit code, or signal with a NULL code);
/// * the `taskrun_local_command_attempts` row keeps the same node/epoch/fence
///   identity as the receipt and a state of `cancelled` or `completed`;
/// * the attempt's legacy exit code matches the sidecar exit shape exactly
///   (`exit_kind=1` → equal code, `exit_kind=2` → `128 + signal`);
/// * the `x2_permission_spent` area binding equals the attempt's managed area
///   identity, and the occupation is released with the same terminal event.
///
/// Recovery-completed cancellations (NULL exit, no sidecar) are admitted by
/// the V51 matcher instead and intentionally fail here.
type SidecarLink = (i64, Option<i64>, Option<i64>, String, Option<i64>);

#[expect(
    clippy::too_many_arguments,
    reason = "reopen admission revalidates the receipt's exact event, identity, and fence linkage"
)]
fn v68_current_route_terminal_matches(
    connection: &Connection,
    taskrun_id: &[u8],
    attempt_id: &[u8],
    node_id: &[u8],
    node_epoch: i64,
    fence: i64,
    terminal_event_id: &[u8],
    terminal_version: i64,
    event: &runne_domain::task_run::TaskRunEvent,
) -> SqliteResult<bool> {
    use runne_domain::task_run::TaskRunEvent;
    if !matches!(
        event,
        TaskRunEvent::TaskRunCancelled | TaskRunEvent::CancellationCompleted
    ) {
        return Ok(false);
    }
    let Ok(taskrun_bytes) = <[u8; 16]>::try_from(taskrun_id) else {
        return Ok(false);
    };
    let taskrun_key = runne_domain::id::TaskRunId::from_bytes(taskrun_bytes);
    match crate::store::taskrun_local_command::permission::no_effect::current_route(
        connection, taskrun_key,
    ) {
        Ok(true) => {}
        _ => return Ok(false),
    }
    let linked: Option<SidecarLink> = connection
        .query_row(
            "SELECT x.exit_kind, x.exit_code, x.signal, a.state, a.exit_code
             FROM x2_permission_terminal x
             JOIN taskrun_local_command_attempts a
               ON a.taskrun_id=x.taskrun_id AND a.attempt_id=x.attempt_id
             WHERE x.taskrun_id=?1 AND x.attempt_id=?2 AND x.fence=?3
               AND x.terminal_kind=1 AND x.event_id=?4 AND x.terminal_version=?5
               AND a.node_id=?6 AND a.node_epoch=?7 AND a.fence=?3
               AND EXISTS(SELECT 1 FROM x2_permission_spent s
                          WHERE s.taskrun_id=x.taskrun_id AND s.attempt_id=x.attempt_id
                            AND s.area_identity=a.managed_area_identity)
               AND EXISTS(SELECT 1 FROM taskrun_assignment_occupations o
                          WHERE o.taskrun_id=x.taskrun_id AND o.fence=x.fence
                            AND o.attempt_id=x.attempt_id AND o.state='released'
                            AND o.dispatch_intent='absent'
                            AND o.release_event_id=x.event_id)",
            rusqlite::params![
                taskrun_id,
                attempt_id,
                fence,
                terminal_event_id,
                terminal_version,
                node_id,
                node_epoch
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },        )
        .optional()?;
    let Some((exit_kind, sidecar_exit, signal, state, attempt_exit)) = linked else {
        return Ok(false);
    };
    let factual_exit_matches = match (exit_kind, sidecar_exit, signal) {
        (1, Some(code), None) => attempt_exit == Some(code),
        (2, None, Some(signal)) if (1..=64).contains(&signal) => {
            attempt_exit == Some(128 + signal)
        }
        _ => false,
    };
    Ok(factual_exit_matches && matches!(state.as_str(), "cancelled" | "completed"))
}
