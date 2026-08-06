//! Sealed-witness process dispatch with one claim and no retry path.

use gocode_platform_ports::process::{
    MonotonicDeadline, ProcessLaunchOutcomeV1, ProcessPlatformPort,
};
use gocode_security::process_contract::ValidatedProcessIntentV1;

use crate::EffectAdmission;

use super::{
    ProcessClaimInputV1, ProcessClaimJournalPort, ProcessContractErrorV1, ProcessControlPortV1,
    ProcessLifecycleStateV1, ProcessMonotonicTimingDispositionV1, ProcessOutputSourcePortV1,
    ProcessUncertainReasonV1,
    journal::{project_claim, transition},
    orchestrator_input::DispatchInputV1,
    orchestrator_settlement::{replay_outcome, settle_not_started, settle_uncertain},
    orchestrator_termination::terminate_with_grace,
};

/// Read-only monotonic clock used by deterministic dispatch control.
pub(crate) trait ProcessMonotonicClockV1 {
    /// Returns the current monotonic tick without consulting wall-clock time.
    fn now_ticks(&self) -> u64;
}

/// Explicit cancellation token queried only at dispatch control points.
pub(crate) trait ProcessCancellationTokenV1 {
    /// Returns whether cancellation has been requested.
    fn is_cancelled(&self) -> bool;
}

/// Result of one sealed process dispatch attempt or its pure replay.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ProcessDispatchOutcomeV1 {
    /// Validation stopped before claim projection or any platform interaction.
    Denied,
    /// A projected record is in the supplied closed lifecycle state.
    State(ProcessLifecycleStateV1),
    /// An exact terminal settlement, with transient output only on its first authorized return.
    Terminal(super::ProcessTerminalResultV1),
}

impl ProcessDispatchOutcomeV1 {
    /// Returns the lifecycle state when a claim exists.
    #[must_use]
    pub const fn state(&self) -> Option<ProcessLifecycleStateV1> {
        match self {
            Self::Denied => None,
            Self::State(state) => Some(*state),
            Self::Terminal(result) => Some(result.settlement().target_state()),
        }
    }
}

/// Stateless authority that derives all dispatch metadata from a sealed witness.
#[derive(Default)]
pub(crate) struct ProcessOrchestratorV1;

impl ProcessOrchestratorV1 {
    /// Creates a stateless sealed-witness process orchestrator.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }

    /// Projects and dispatches one already admitted sealed process intent.
    ///
    /// Caller-supplied digests and identity bindings are intentionally absent:
    /// both are derived from `intent` before the platform boundary.
    ///
    /// CONTRACT_ONLY: runtime composition is intentionally deferred and this
    /// internal entry point has no public re-export.
    ///
    /// # Errors
    ///
    /// Returns a typed journal failure without invoking a substitute operation.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch<P, C, J, S, K, T>(
        &self,
        intent: ValidatedProcessIntentV1,
        admission: &EffectAdmission,
        journal: &mut J,
        platform: &P,
        control: &C,
        output: &mut S,
        clock: &K,
        cancellation: &T,
    ) -> Result<ProcessDispatchOutcomeV1, ProcessContractErrorV1>
    where
        P: ProcessPlatformPort,
        C: ProcessControlPortV1,
        J: ProcessClaimJournalPort,
        S: ProcessOutputSourcePortV1,
        K: ProcessMonotonicClockV1,
        T: ProcessCancellationTokenV1,
    {
        let input = DispatchInputV1::from_validated(&intent)?;
        self.dispatch_input(
            input,
            admission,
            journal,
            platform,
            control,
            output,
            clock,
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn dispatch_input<P, C, J, S, K, T>(
        &self,
        input: DispatchInputV1,
        admission: &EffectAdmission,
        journal: &mut J,
        platform: &P,
        control: &C,
        output: &mut S,
        clock: &K,
        cancellation: &T,
    ) -> Result<ProcessDispatchOutcomeV1, ProcessContractErrorV1>
    where
        P: ProcessPlatformPort,
        C: ProcessControlPortV1,
        J: ProcessClaimJournalPort,
        S: ProcessOutputSourcePortV1,
        K: ProcessMonotonicClockV1,
        T: ProcessCancellationTokenV1,
    {
        let dispatch_started = clock.now_ticks();
        let deadline = match MonotonicDeadline::checked_after(dispatch_started, input.timeout_ticks)
        {
            Ok(deadline) => deadline,
            Err(_) => return Ok(ProcessDispatchOutcomeV1::Denied),
        };
        if deadline.is_reached(clock.now_ticks()).unwrap_or(true)
            || (input.cancellation_permitted && cancellation.is_cancelled())
        {
            return Ok(ProcessDispatchOutcomeV1::Denied);
        }
        let claim = ProcessClaimInputV1::new(
            admission,
            input.digest,
            input.claim_binding.clone(),
            deadline,
        )?;
        let (record, claimed) = project_claim(journal, &claim)?;
        if !claimed {
            return Ok(replay_outcome(record));
        }
        transition(journal, &claim, ProcessLifecycleStateV1::Launching)?;
        let prepared = match platform.validate_and_prepare(&input.request, deadline) {
            Ok(prepared) => prepared,
            Err(_) => {
                return settle_uncertain(
                    journal,
                    &claim,
                    ProcessMonotonicTimingDispositionV1::WithinDeadline,
                    ProcessUncertainReasonV1::EvidenceUnavailable,
                );
            }
        };
        match platform.launch(prepared, &input.binding, deadline) {
            Ok(ProcessLaunchOutcomeV1::NoProcessStarted(evidence))
                if evidence.binding() == &input.binding =>
            {
                settle_not_started(
                    journal,
                    &claim,
                    evidence,
                    ProcessMonotonicTimingDispositionV1::WithinDeadline,
                )
            }
            Ok(ProcessLaunchOutcomeV1::Launched(evidence))
                if evidence.binding() == &input.binding =>
            {
                transition(journal, &claim, ProcessLifecycleStateV1::Running)?;
                match deadline.is_reached(clock.now_ticks()) {
                    Ok(true) => terminate_with_grace(
                        &input,
                        &claim,
                        journal,
                        platform,
                        control,
                        output,
                        clock,
                        ProcessMonotonicTimingDispositionV1::DeadlineReached,
                    ),
                    Ok(false) if input.cancellation_permitted && cancellation.is_cancelled() => {
                        terminate_with_grace(
                            &input,
                            &claim,
                            journal,
                            platform,
                            control,
                            output,
                            clock,
                            ProcessMonotonicTimingDispositionV1::CancellationObservedBeforeDeadline,
                        )
                    }
                    Ok(false) => Ok(ProcessDispatchOutcomeV1::State(
                        ProcessLifecycleStateV1::Running,
                    )),
                    Err(_) => settle_uncertain(
                        journal,
                        &claim,
                        ProcessMonotonicTimingDispositionV1::TimingUncertain,
                        ProcessUncertainReasonV1::TimingUnavailable,
                    ),
                }
            }
            Ok(_) | Err(_) => settle_uncertain(
                journal,
                &claim,
                ProcessMonotonicTimingDispositionV1::WithinDeadline,
                ProcessUncertainReasonV1::EvidenceUnavailable,
            ),
        }
    }
}
