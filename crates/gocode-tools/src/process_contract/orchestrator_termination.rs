use gocode_platform_ports::process::{MonotonicDeadline, ProcessPlatformPort};

use super::{
    ProcessClaimInputV1, ProcessClaimJournalPort, ProcessContractErrorV1, ProcessControlPortV1,
    ProcessDispatchOutcomeV1, ProcessLifecycleStateV1, ProcessMonotonicClockV1,
    ProcessMonotonicTimingDispositionV1, ProcessOutputSourcePortV1, ProcessUncertainReasonV1,
    journal::transition,
    orchestrator_input::{DispatchInputV1, exact_verified_terminal},
    orchestrator_settlement::{collect_and_settle_terminal, settle_uncertain},
};

#[allow(clippy::too_many_arguments)]
pub(super) fn terminate_with_grace<P, C, J, S, K>(
    input: &DispatchInputV1,
    claim: &ProcessClaimInputV1,
    journal: &mut J,
    platform: &P,
    control: &C,
    output: &mut S,
    clock: &K,
    timing: ProcessMonotonicTimingDispositionV1,
) -> Result<ProcessDispatchOutcomeV1, ProcessContractErrorV1>
where
    P: ProcessPlatformPort,
    C: ProcessControlPortV1,
    J: ProcessClaimJournalPort,
    S: ProcessOutputSourcePortV1,
    K: ProcessMonotonicClockV1,
{
    transition(journal, claim, ProcessLifecycleStateV1::Terminating)?;
    match control.request_graceful(&input.binding) {
        Err(gocode_platform_ports::process::ProcessPlatformFailure::LifecycleControlMismatch) => {
            return settle_uncertain(
                journal,
                claim,
                timing,
                ProcessUncertainReasonV1::EvidenceUnavailable,
            );
        }
        Err(_) => {
            return force_terminal(
                input,
                claim,
                journal,
                platform,
                output,
                MonotonicDeadline::current(clock.now_ticks()),
                timing,
            );
        }
        Ok(()) => {}
    }
    let started = clock.now_ticks();
    let grace = MonotonicDeadline::checked_after(started, 1)
        .unwrap_or_else(|_| MonotonicDeadline::current(started));
    match control.wait_for_grace(&input.binding, grace) {
        Ok(Some(evidence)) if exact_verified_terminal(&evidence, &input.binding) => {
            collect_and_settle_terminal(
                journal,
                claim,
                evidence,
                &input.output_bounds,
                &input.output_caller,
                output,
                timing,
            )
        }
        Ok(None) => force_terminal(input, claim, journal, platform, output, grace, timing),
        Ok(Some(_))
        | Err(gocode_platform_ports::process::ProcessPlatformFailure::LifecycleControlMismatch) => {
            settle_uncertain(
                journal,
                claim,
                timing,
                ProcessUncertainReasonV1::EvidenceUnavailable,
            )
        }
        Err(_) => force_terminal(
            input,
            claim,
            journal,
            platform,
            output,
            MonotonicDeadline::current(clock.now_ticks()),
            timing,
        ),
    }
}

pub(super) fn force_terminal<P, J, S>(
    input: &DispatchInputV1,
    claim: &ProcessClaimInputV1,
    journal: &mut J,
    platform: &P,
    output: &mut S,
    deadline: MonotonicDeadline,
    timing: ProcessMonotonicTimingDispositionV1,
) -> Result<ProcessDispatchOutcomeV1, ProcessContractErrorV1>
where
    P: ProcessPlatformPort,
    J: ProcessClaimJournalPort,
    S: ProcessOutputSourcePortV1,
{
    match platform.terminate(&input.binding, deadline) {
        Ok(evidence) if exact_verified_terminal(&evidence, &input.binding) => {
            collect_and_settle_terminal(
                journal,
                claim,
                evidence,
                &input.output_bounds,
                &input.output_caller,
                output,
                timing,
            )
        }
        Ok(_) | Err(_) => settle_uncertain(
            journal,
            claim,
            timing,
            ProcessUncertainReasonV1::EvidenceUnavailable,
        ),
    }
}
