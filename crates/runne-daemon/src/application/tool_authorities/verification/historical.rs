use super::*;
use runne_domain::agent_loop::LoopDisposition;

pub(super) fn verify(
    authority: &D2ToolLoopAuthority,
    taskrun_id: runne_domain::id::TaskRunId,
) -> Result<PlanEvaluation, VerificationQueryError> {
    let full = authority
        .store
        .load_task_run(taskrun_id)
        .map_err(|_| VerificationQueryError::Unavailable)?;
    let completed =
        TaskRun::replay(&full.events).map_err(|_| VerificationQueryError::InvalidBinding)?;
    if completed.state() != TaskRunState::Succeeded
        || !full.events.iter().any(|event| {
            matches!(
                event.payload(),
                runne_domain::task_run::TaskRunEvent::TaskRunCompleted { .. }
            )
        })
    {
        return Err(VerificationQueryError::Stale);
    }
    let mut evaluations = full
        .events
        .iter()
        .filter_map(|event| match event.payload() {
            runne_domain::task_run::TaskRunEvent::LoopCycleCompleted {
                cycle_id,
                attempt_id,
                disposition:
                    LoopDisposition::Complete {
                        plan_evaluation_ref,
                    },
            } => Some((*cycle_id, *attempt_id, plan_evaluation_ref.clone())),
            _ => None,
        });
    let (cycle_id, attempt_id, reference) = evaluations
        .next()
        .ok_or(VerificationQueryError::InvalidBinding)?;
    if evaluations.next().is_some()
        || reference.taskrun_id != taskrun_id
        || reference.evaluated_stream_head as usize > full.events.len()
    {
        return Err(VerificationQueryError::InvalidBinding);
    }
    let head = usize::try_from(reference.evaluated_stream_head)
        .map_err(|_| VerificationQueryError::InvalidBinding)?;
    let prefix = runne_application::ports::LoadedStream {
        events: full.events[..head].to_vec(),
        current_version: reference.evaluated_stream_head,
        last_event_id: full
            .events
            .get(head.saturating_sub(1))
            .map(|event| *event.event_id()),
    };
    let before_completion =
        TaskRun::replay(&prefix.events).map_err(|_| VerificationQueryError::InvalidBinding)?;
    let before_snapshot = before_completion.snapshot_v1();
    let active = before_snapshot
        .active_cycle()
        .ok_or(VerificationQueryError::InvalidBinding)?;
    if before_completion.state() != TaskRunState::Running
        || active.cycle_id != cycle_id
        || active.attempt_id != attempt_id
        || active.state != LoopCycleState::Evaluating
    {
        return Err(VerificationQueryError::InvalidBinding);
    }
    let derived = authority.evaluate_stream(taskrun_id, prefix, Some(&reference), true)?;
    (derived.reference == reference)
        .then_some(derived)
        .ok_or(VerificationQueryError::DigestMismatch)
}
