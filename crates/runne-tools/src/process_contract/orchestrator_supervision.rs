use runne_platform_ports::process::{ProcessPlatformPort, ProcessTerminalEvidenceV1};

use crate::EffectAdmission;

use super::{
    ProcessClaimInputV1, ProcessClaimJournalPort, ProcessContractErrorV1, ProcessControlPortV1,
    ProcessDispatchOutcomeV1, ProcessLifecycleStateV1, ProcessMonotonicClockV1,
    ProcessMonotonicTimingDispositionV1, ProcessOrchestratorV1, ProcessOutputSourcePortV1,
    ProcessUncertainReasonV1,
    journal::recover_after_reopen,
    orchestrator_input::{DispatchInputV1, exact_verified_terminal, matches_claim},
    orchestrator_settlement::{collect_and_settle_terminal, replay_outcome, settle_uncertain},
    orchestrator_termination::{force_terminal, terminate_with_grace},
};

impl ProcessOrchestratorV1 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn supervise_input<P, C, J, S, K, T>(
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
        T: super::ProcessCancellationTokenV1,
    {
        let key = super::ProcessClaimKeyV1::new(admission.permit_id.clone());
        let record = journal
            .read(&key)?
            .ok_or(ProcessContractErrorV1::AdmissionMissing)?;
        if !matches_claim(record.input(), &input, admission) {
            return Err(ProcessContractErrorV1::ClaimProjectionConflict);
        }
        if record.settlement().is_some() {
            return Ok(replay_outcome(record));
        }
        let claim = record.input().clone();
        match record.state() {
            ProcessLifecycleStateV1::Claimed | ProcessLifecycleStateV1::Launching => {
                recover_after_reopen(journal, &key)?.map_or_else(
                    || Err(ProcessContractErrorV1::AdmissionMissing),
                    |record| Ok(replay_outcome(record)),
                )
            }
            ProcessLifecycleStateV1::Running => self.supervise_running(
                &input,
                &claim,
                journal,
                platform,
                control,
                output,
                clock,
                cancellation,
            ),
            ProcessLifecycleStateV1::Terminating => force_terminal(
                &input,
                &claim,
                journal,
                platform,
                output,
                claim.deadline(),
                ProcessMonotonicTimingDispositionV1::DeadlineReached,
            ),
            _ => Ok(replay_outcome(record)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn supervise_running<P, C, J, S, K, T>(
        &self,
        input: &DispatchInputV1,
        claim: &ProcessClaimInputV1,
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
        T: super::ProcessCancellationTokenV1,
    {
        match claim.deadline().is_reached(clock.now_ticks()) {
            Err(_) => settle_uncertain(
                journal,
                claim,
                ProcessMonotonicTimingDispositionV1::TimingUncertain,
                ProcessUncertainReasonV1::TimingUnavailable,
            ),
            Ok(true) => terminate_with_grace(
                input,
                claim,
                journal,
                platform,
                control,
                output,
                clock,
                ProcessMonotonicTimingDispositionV1::DeadlineReached,
            ),
            Ok(false) if input.cancellation_permitted && cancellation.is_cancelled() => {
                terminate_with_grace(
                    input,
                    claim,
                    journal,
                    platform,
                    control,
                    output,
                    clock,
                    ProcessMonotonicTimingDispositionV1::CancellationObservedBeforeDeadline,
                )
            }
            Ok(false) => self.observe_running(input, claim, journal, control, output),
        }
    }

    fn observe_running<C, J, S>(
        &self,
        input: &DispatchInputV1,
        claim: &ProcessClaimInputV1,
        journal: &mut J,
        control: &C,
        output: &mut S,
    ) -> Result<ProcessDispatchOutcomeV1, ProcessContractErrorV1>
    where
        C: ProcessControlPortV1,
        J: ProcessClaimJournalPort,
        S: ProcessOutputSourcePortV1,
    {
        match control.observe_terminal(&input.binding, claim.deadline()) {
            Ok(Some(evidence)) if exact_verified_terminal(&evidence, &input.binding) => {
                collect_and_settle_terminal(
                    journal,
                    claim,
                    evidence,
                    &input.output_bounds,
                    &input.output_caller,
                    output,
                    ProcessMonotonicTimingDispositionV1::WithinDeadline,
                )
            }
            Ok(None) => Ok(ProcessDispatchOutcomeV1::State(
                ProcessLifecycleStateV1::Running,
            )),
            Ok(Some(evidence)) => settle_uncertain(
                journal,
                claim,
                ProcessMonotonicTimingDispositionV1::WithinDeadline,
                evidence_reason(&evidence),
            ),
            Err(_) => settle_uncertain(
                journal,
                claim,
                ProcessMonotonicTimingDispositionV1::WithinDeadline,
                ProcessUncertainReasonV1::EvidenceUnavailable,
            ),
        }
    }
}

fn evidence_reason(evidence: &ProcessTerminalEvidenceV1) -> ProcessUncertainReasonV1 {
    if evidence.tree_cleanup() != runne_platform_ports::process::ProcessTreeCleanupV1::Verified {
        ProcessUncertainReasonV1::TreeCleanupUnverified
    } else {
        ProcessUncertainReasonV1::EvidenceUnavailable
    }
}
