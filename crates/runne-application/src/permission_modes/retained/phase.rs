//! Clock, deadline, and execution-phase observations; no clock is inferred.

use super::model::{
    RetainedClockObservationV1, RetainedCurrentFactsV1, RetainedNotEvaluableReasonV1,
    RetainedOriginalContextV1, RetainedPhaseObservationV1, RetainedPhaseV1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PhaseStatus {
    BeforeGo,
    Running,
    StopRequired,
}

fn clocks_ordered(
    original: RetainedClockObservationV1,
    current: RetainedClockObservationV1,
) -> bool {
    original.epoch == current.epoch
        && current.wall_unix_ms >= original.wall_unix_ms
        && current.monotonic_ms >= original.monotonic_ms
        && current.wall_unix_ms > 0
        && current.epoch > 0
}

fn original_deadline_passed(
    context: &RetainedOriginalContextV1,
    current: &RetainedCurrentFactsV1,
) -> bool {
    let now = current.observed_clock.wall_unix_ms;
    now >= context.invocation_deadline_unix_ms
        || context
            .selection_expiry_unix_ms
            .is_some_and(|expiry| now >= expiry)
        || current
            .selection
            .expires_at_unix_ms
            .is_some_and(|expiry| now >= expiry)
}

pub(super) fn observe_phase(
    original: &crate::permission_modes::LocalCommandPermissionBindingV1,
    context: &RetainedOriginalContextV1,
    current: &RetainedCurrentFactsV1,
    phase: RetainedPhaseObservationV1,
) -> Result<PhaseStatus, RetainedNotEvaluableReasonV1> {
    let now = current.observed_clock;
    if !clocks_ordered(context.admission_clock, now) {
        return Err(RetainedNotEvaluableReasonV1::ClockObservationInconsistent);
    }
    if now.wall_unix_ms >= current.assignment_lease_deadline_unix_ms {
        return Err(RetainedNotEvaluableReasonV1::AssignmentLeaseExpired);
    }
    match phase.phase {
        RetainedPhaseV1::BeforeGo => {
            if phase.runtime_start.is_some() || phase.elapsed_runtime_ms.is_some() {
                return Err(RetainedNotEvaluableReasonV1::PhaseObservationInconsistent);
            }
            if original_deadline_passed(context, current) {
                return Err(RetainedNotEvaluableReasonV1::OriginalGrantExpired);
            }
            Ok(PhaseStatus::BeforeGo)
        }
        RetainedPhaseV1::Running | RetainedPhaseV1::Terminal => {
            let (Some(start), Some(elapsed)) = (phase.runtime_start, phase.elapsed_runtime_ms)
            else {
                return Err(RetainedNotEvaluableReasonV1::ClockObservationInconsistent);
            };
            let measured_elapsed = now
                .monotonic_ms
                .checked_sub(start.monotonic_start_ms)
                .ok_or(RetainedNotEvaluableReasonV1::ClockObservationInconsistent)?;
            let max_runtime = original.limits().max_runtime_ms();
            let _runtime_deadline = start
                .monotonic_start_ms
                .checked_add(max_runtime)
                .ok_or(RetainedNotEvaluableReasonV1::ClockObservationInconsistent)?;
            if start.original_binding_digest != original.digest()
                || start.invocation_id != original.invocation_id()
                || start.clock_epoch != now.epoch
                || start.clock_epoch != context.admission_clock.epoch
                || start.monotonic_start_ms < context.admission_clock.monotonic_ms
                || start.wall_start_unix_ms < context.admission_clock.wall_unix_ms
                || start.wall_start_unix_ms > now.wall_unix_ms
                || start.wall_start_unix_ms <= 0
                || elapsed != measured_elapsed
            {
                return Err(RetainedNotEvaluableReasonV1::ClockObservationInconsistent);
            }
            if elapsed >= max_runtime || original_deadline_passed(context, current) {
                return Ok(PhaseStatus::StopRequired);
            }
            if phase.phase == RetainedPhaseV1::Terminal {
                return Ok(PhaseStatus::StopRequired);
            }
            Ok(PhaseStatus::Running)
        }
    }
}
