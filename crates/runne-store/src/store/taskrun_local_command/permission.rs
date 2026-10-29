mod admission_checks;
#[cfg(target_os = "linux")]
mod approval;
#[cfg(target_os = "linux")]
mod burn;
#[cfg(target_os = "linux")]
mod burn_guard;
#[cfg(target_os = "linux")]
mod cancel_before_release;
#[cfg(target_os = "linux")]
mod cancel_event;
#[cfg(target_os = "linux")]
mod capture;
#[cfg(target_os = "linux")]
mod capture_checks;
pub(crate) mod codec;
#[cfg(target_os = "linux")]
mod exit_record;
mod model;
pub(crate) mod no_effect;
mod no_effect_append;
mod no_effect_capture;
mod no_effect_policy_stop;
mod no_effect_precapture;
mod observation;
mod original_approval_facts;
mod owner;
mod read;
mod retained_fanout;
mod retained_policy;
mod retained_policy_rows;
pub(in crate::store) use retained_fanout::can_retain_in_tx;
#[cfg(target_os = "linux")]
mod release;
#[cfg(target_os = "linux")]
mod release_guard;
pub(crate) mod retained_context;
pub(crate) mod retained_context_codec;
mod retained_context_correlation;
mod retained_context_cursor;
mod retained_context_policy_wire;
mod retained_context_scope_wire;
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod retained_context_tests;
pub(crate) mod stop;
pub use read::LocalCommandPermissionCaptureV1;
#[cfg(target_os = "linux")]
mod terminal;
#[cfg(target_os = "linux")]
mod terminal_prepare;
#[cfg(target_os = "linux")]
mod terminal_settle;
#[cfg(target_os = "linux")]
mod terminal_validate;
#[cfg(target_os = "linux")]
mod terminal_write;
pub(crate) use no_effect_append::append_release_event;
use runne_domain::{
    command::TerminalResult,
    task_run::{TaskRunEvent, TaskRunState},
};
use rusqlite::{OptionalExtension, Transaction};
#[cfg(target_os = "linux")]
pub use terminal::LocalCommandPermissionTerminalOutputV1;
#[cfg(target_os = "linux")]
pub(crate) use terminal::PermissionTerminalCommitV1;
#[cfg(target_os = "linux")]
pub(crate) use terminal::validate_duplicate as validate_duplicate_terminal;
#[cfg(target_os = "linux")]
pub(crate) use terminal_prepare::prepare as prepare_terminal;
#[cfg(target_os = "linux")]
pub(crate) use terminal_settle::settle_and_record as write_terminal;
#[cfg(target_os = "linux")]
pub(crate) use terminal_validate::validate as validate_terminal;
#[cfg(not(target_os = "linux"))]
pub(crate) struct PermissionTerminalCommitV1<'child, 'area>(
    std::marker::PhantomData<&'child &'area ()>,
);

/// Immutable cutover classification for one submitted local command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCommandPermissionRoute {
    /// Positively validated V1 approval and release lifecycle.
    LegacyBound,
    /// Historical terminal/no-effect row; it must never be executed again.
    LegacyTerminal,
    /// New command requiring retained permission capture and admission.
    CurrentPermission,
}

mod stop_entry;

pub(crate) fn record_cancellation_stops(
    tx: &Transaction<'_>,
    taskrun_id: runne_domain::id::TaskRunId,
    version: u64,
    event_id: &[u8],
    stopped_at: i64,
) -> Result<(), runne_application::ports::EventStoreError> {
    use runne_application::ports::EventStoreError;
    let mut statement = tx
        .prepare(
            "SELECT b.attempt_id,b.binding_digest,b.binding FROM x2_permission_bindings b
         JOIN taskrun_local_permission_routes r USING(taskrun_id)
         JOIN taskrun_local_command_attempts a USING(taskrun_id)
         WHERE b.taskrun_id=?1 AND r.route=2 AND r.provenance=3 AND r.cutover_version=68
           AND a.attempt_id=b.attempt_id AND a.fence=b.fence
           AND a.state IN ('approved','launch_intent','release_reserved','running','completed')
           AND NOT EXISTS(SELECT 1 FROM x2_permission_terminal t
             WHERE t.taskrun_id=b.taskrun_id AND t.attempt_id=b.attempt_id)",
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let rows = statement
        .query_map([taskrun_id.as_bytes()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|_| EventStoreError::CorruptData)?;
    let rows = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| EventStoreError::CorruptData)?;
    drop(statement);
    for (attempt, digest, bytes) in rows {
        let record = codec::decode(&bytes).map_err(|_| EventStoreError::CorruptData)?;
        if !codec::digest_matches(&bytes, &digest)
            || record.taskrun_id != *taskrun_id.as_bytes()
            || record.attempt_id.as_slice() != attempt.as_slice()
        {
            return Err(EventStoreError::CorruptData);
        }
        let attempt: [u8; 16] = attempt
            .try_into()
            .map_err(|_| EventStoreError::CorruptData)?;
        stop::record_stop(
            tx,
            taskrun_id.as_bytes(),
            &attempt,
            &digest,
            1,
            version,
            event_id,
            stopped_at,
        )?;
    }
    Ok(())
}

impl super::super::StoreTransaction {
    /// Loads the immutable V68 route and rejects missing or malformed rows.
    pub fn local_command_permission_route(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
    ) -> Result<LocalCommandPermissionRoute, runne_application::ports::EventStoreError> {
        let reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| runne_application::ports::EventStoreError::Unavailable)?;
        let route: Option<(i64, i64, i64)> = reader
            .query_row(
                "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes WHERE taskrun_id=?1",
                [taskrun_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| runne_application::ports::EventStoreError::CorruptData)?;
        match route {
            Some((1, 1, 68)) => Ok(LocalCommandPermissionRoute::LegacyBound),
            Some((1, 2, 68)) => Ok(LocalCommandPermissionRoute::LegacyTerminal),
            Some((2, 3, 68)) => Ok(LocalCommandPermissionRoute::CurrentPermission),
            _ => Err(runne_application::ports::EventStoreError::CorruptData),
        }
    }
}

pub(super) fn require_legacy_bound_route(
    tx: &Transaction<'_>,
    taskrun_id: runne_domain::id::TaskRunId,
) -> Result<(), runne_application::ports::EventStoreError> {
    let route: Option<(i64, i64, i64)> = tx
        .query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| runne_application::ports::EventStoreError::CorruptData)?;
    if route == Some((1, 1, 68)) {
        Ok(())
    } else {
        Err(runne_application::ports::EventStoreError::CorruptData)
    }
}

pub(super) fn terminal_matches_exit(
    event: &TaskRunEvent,
    state: &TaskRunState,
    exit_code: i32,
    current_permission: bool,
) -> bool {
    match (state, event) {
        (TaskRunState::Succeeded, TaskRunEvent::TaskRunCompleted { result }) => match result {
            TerminalResult::Success => exit_code == 0,
            TerminalResult::Failure { reason } => {
                exit_code != 0 && reason == &format!("local_command_exit_{exit_code}")
            }
        },
        (TaskRunState::Failed, TaskRunEvent::TaskRunFailed { reason })
            if current_permission && reason == "local_command_policy_stopped_v1" =>
        {
            (0..=255).contains(&exit_code)
        }
        (TaskRunState::Failed, TaskRunEvent::TaskRunFailed { reason })
            if current_permission && (129..=192).contains(&exit_code) =>
        {
            reason == &format!("local_command_signal_v1_{}", exit_code - 128)
        }
        (TaskRunState::Cancelled, TaskRunEvent::CancellationCompleted) if current_permission => {
            (0..=255).contains(&exit_code)
        }
        _ => false,
    }
}

pub use owner::{
    PermissionRootFenceGuardV1, PermissionRootFenceOwnerV1, PermissionRootFenceRequestV1,
};

#[cfg(all(test, target_os = "linux"))]
mod tests_release_guard;
