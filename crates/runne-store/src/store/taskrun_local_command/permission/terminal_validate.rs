use super::{
    capture::{verify_current_selection, verify_submit_origin},
    model::{
        load_capture, now_ms, observation_matches, validate_area, verify_admission,
        verify_workspace,
    },
    terminal::{PermissionTerminalCommitV1, PermissionTerminalProof},
};
use crate::store::StoreTransaction;
use crate::store::taskrun_claim;
use runne_application::{
    commands::CommandOutcome,
    ports::{CommandCommit, CommitError},
};
use runne_domain::{
    command::TerminalResult,
    task_run::{TaskRunEvent, TaskRunState},
};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;
use rusqlite::{OptionalExtension, Transaction, params};

type SpentPermissionProofRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

pub(crate) fn validate(
    tx: &Transaction<'_>,
    store: &StoreTransaction,
    terminal: &PermissionTerminalCommitV1<'_, '_>,
    payload: &CommandCommit,
) -> Result<PermissionTerminalProof, CommitError> {
    let identity = terminal.identity;
    let binding = terminal.binding;
    let child = terminal.child;
    let invalid = super::terminal::terminal_integrity_error;
    if identity != binding.assignment()
        || child.original_binding() != binding
        || !child.was_released()
        || payload.events.len() != 1
    {
        return Err(invalid());
    }
    taskrun_claim::verify_active_assignment(tx, identity).map_err(|_| invalid())?;
    let stream = taskrun_claim::stream_validate::verify_stream(tx, identity.taskrun_id, None)
        .map_err(|_| invalid())?;
    if stream.version != payload.expected_version
        || !matches!(
            stream.state,
            TaskRunState::Running | TaskRunState::Cancelling
        )
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
    verify_submit_origin(store, tx, binding).map_err(|_| invalid())?;
    verify_current_selection(
        tx,
        &binding.selection().scope,
        &terminal.current_selection,
        runne_application::project_trust::ProjectTrustProjectId::from_bytes(
            *binding.project_id().as_bytes(),
        ),
    )
    .map_err(|_| invalid())?;
    let policy_stop = terminal.current_selection != *binding.selection()
        || terminal.trust != binding.closed_rules_snapshot()
        || terminal.trust.record.status
            == runne_application::project_trust::ProjectTrustStatus::Untrusted
        || terminal
            .current_selection
            .expires_at_unix_ms
            .is_some_and(|expiry| expiry <= now_ms())
        || binding.approval().expires_at_unix_ms <= now_ms();
    if policy_stop != terminal.policy_stop {
        return Err(invalid());
    }
    verify_workspace(tx, binding).map_err(|_| invalid())?;
    let capture = load_capture(tx, identity, binding, false).map_err(|_| invalid())?;
    let binding_digest: [u8; 32] = capture.0.as_slice().try_into().map_err(|_| invalid())?;
    let durable_stop = super::stop::stop_reason(
        tx,
        identity.taskrun_id.as_bytes(),
        identity.attempt_id.as_bytes(),
        &binding_digest,
    )
    .map_err(|_| invalid())?;
    let cancellation_stop = durable_stop == Some(1);
    let durable_policy_stop = matches!(durable_stop, Some(2..=5));
    let stopped = cancellation_stop || durable_policy_stop;
    if durable_stop == Some(6)
        || terminal.policy_stop && !stopped
        || stream.state == TaskRunState::Cancelling && !stopped
        || cancellation_stop && stream.state != TaskRunState::Cancelling
    {
        return Err(invalid());
    }
    verify_admission(
        tx,
        binding,
        &binding_digest,
        now_ms(),
        durable_stop.is_some(),
    )
    .map_err(|_| invalid())?;

    let observation = child.observation();
    if !observation_matches(binding, observation)
        || observation.owner_id().as_slice() != capture.2.as_slice()
        || observation.owner_generation().to_be_bytes().as_slice() != capture.3.as_slice()
    {
        return Err(invalid());
    }
    let evidence = child.terminal_evidence().map_err(|_| invalid())?;
    evidence.revalidate_empty_area().map_err(|_| invalid())?;
    let area_identity = *evidence.area_identity();
    validate_area(identity, &area_identity).map_err(|_| invalid())?;
    if child.area_identity() != area_identity {
        return Err(invalid());
    }
    let spent: Option<SpentPermissionProofRow> = tx
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
    if !spent.is_some_and(|(digest, invocation, area, owner, generation)| {
        digest.as_slice() == capture.0.as_slice()
            && invocation.as_slice() == binding.invocation_id().as_bytes()
            && area.as_slice() == area_identity.as_slice()
            && owner.as_slice() == capture.2.as_slice()
            && generation.as_slice() == capture.3.as_slice()
    }) {
        return Err(invalid());
    }

    let expected_version = payload
        .expected_version
        .checked_add(1)
        .ok_or_else(invalid)?;
    let event = &payload.events[0];
    let exit_kind = evidence.leader_exit_kind();
    let legacy_exit_code = match exit_kind {
        LinuxLeaderExitKindV1::Exited { code } => i32::from(code),
        LinuxLeaderExitKindV1::Signaled { signal, .. } if (1..=64).contains(&signal) => {
            128 + signal
        }
        LinuxLeaderExitKindV1::Signaled { .. } => return Err(invalid()),
    };
    let complete_outcome = matches!(
        &payload.command_result,
        CommandOutcome::TaskRunCompleted { taskrun_id, new_version }
            if *taskrun_id == identity.taskrun_id && *new_version == expected_version
    );
    let event_matches = match (&stream.state, event.payload()) {
        (TaskRunState::Cancelling, TaskRunEvent::CancellationCompleted) if stopped => matches!(
            &payload.command_result,
            CommandOutcome::TaskRunCancellationCompleted { taskrun_id, new_version }
                if *taskrun_id == identity.taskrun_id && *new_version == expected_version
        ),
        (TaskRunState::Running, TaskRunEvent::TaskRunFailed { reason })
            if durable_policy_stop && reason == "local_command_policy_stopped_v1" =>
        {
            complete_outcome
        }
        (TaskRunState::Running, TaskRunEvent::TaskRunFailed { reason })
            if !durable_policy_stop
                && matches!(exit_kind, LinuxLeaderExitKindV1::Signaled { .. }) =>
        {
            let LinuxLeaderExitKindV1::Signaled { signal, .. } = exit_kind else {
                return Err(invalid());
            };
            reason == &format!("local_command_signal_v1_{signal}") && complete_outcome
        }
        (
            TaskRunState::Running,
            TaskRunEvent::TaskRunCompleted {
                result: TerminalResult::Success,
            },
        ) if !durable_policy_stop && exit_kind == (LinuxLeaderExitKindV1::Exited { code: 0 }) => {
            complete_outcome
        }
        (
            TaskRunState::Running,
            TaskRunEvent::TaskRunCompleted {
                result: TerminalResult::Failure { reason },
            },
        ) if !durable_policy_stop
            && matches!(exit_kind, LinuxLeaderExitKindV1::Exited { code: 1..=255 }) =>
        {
            reason == &format!("local_command_exit_{legacy_exit_code}") && complete_outcome
        }
        _ => false,
    };
    if !event_matches
        || event.command_id() != &payload.command_id
        || event.correlation_id() != &runne_domain::id::AggregateId::TaskRun(identity.taskrun_id)
    {
        return Err(invalid());
    }
    Ok(PermissionTerminalProof {
        binding_digest: capture.0.as_slice().try_into().map_err(|_| invalid())?,
        area_identity,
        event_id: *event.event_id(),
        terminal_version: expected_version,
        exit_kind,
        legacy_exit_code,
        stopped,
    })
}
