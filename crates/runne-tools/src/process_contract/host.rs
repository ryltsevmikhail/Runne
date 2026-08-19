use std::cell::Cell;

use runne_platform::process_contract::{ProcessPlatformStubV1, ProcessPlatformTargetV1};
use runne_platform_ports::process::{
    MonotonicDeadline, ProcessLifecycleBindingV1, ProcessPlatformFailure, ProcessStubDisposition,
    ProcessTerminalEvidenceV1,
};
use runne_security::process_contract::ValidatedProcessIntentV1;

use crate::EffectAdmission;

use super::{
    ProcessCancellationTokenV1, ProcessClaimJournalMemorySnapshotV1, ProcessClaimJournalMemoryV1,
    ProcessContractErrorV1, ProcessControlPortV1, ProcessDispatchOutcomeV1,
    ProcessLifecycleStateV1, ProcessMonotonicClockV1, ProcessOrchestratorV1,
    ProcessOutputReadBudgetV1, ProcessOutputSourceErrorV1, ProcessOutputSourceEventV1,
    ProcessOutputSourcePortV1, ProcessOutputStopEvidenceV1, ProcessOutputStopReasonV1,
    ProcessTerminalResultV1,
};

/// Public result of one sealed host dispatch or its exact replay.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
pub enum ProcessHostOutcomeV1 {
    /// Dispatch stopped before a claim was projected.
    Denied,
    /// The exact claim is in a non-output lifecycle state.
    State(ProcessLifecycleStateV1),
    /// The exact claim has terminal metadata and authorized transient output.
    Terminal(ProcessTerminalResultV1),
}

/// Opaque recovery state for a sealed process contract host.
pub struct ProcessContractHostSnapshotV1 {
    journal: ProcessClaimJournalMemorySnapshotV1,
    target: ProcessPlatformTargetV1,
    clock_seed: u64,
}

/// Closed runtime host for the deterministic in-memory process contract.
pub struct ProcessContractHostV1 {
    journal: ProcessClaimJournalMemoryV1,
    target: ProcessPlatformTargetV1,
    platform: ProcessPlatformStubV1,
    clock: HostClock,
    control: HostControl,
    output: HostOutput,
    cancellation: NeverCancelled,
}

impl ProcessContractHostV1 {
    /// Selects a closed platform stub and composes only private deterministic adapters.
    #[must_use]
    pub fn new(
        journal: ProcessClaimJournalMemoryV1,
        target: ProcessPlatformTargetV1,
        clock_seed: u64,
    ) -> Self {
        Self {
            journal,
            target,
            platform: ProcessPlatformStubV1::for_target(target),
            clock: HostClock::new(clock_seed),
            control: HostControl,
            output: HostOutput,
            cancellation: NeverCancelled,
        }
    }

    /// Consumes the live host at an explicit recovery point to prevent parallel composition.
    #[must_use]
    pub fn snapshot(self) -> ProcessContractHostSnapshotV1 {
        ProcessContractHostSnapshotV1 {
            journal: self.journal.snapshot(),
            target: self.target,
            clock_seed: self.clock.seed,
        }
    }

    /// Reopens a consumed host snapshot with its original closed target and clock seed.
    #[must_use]
    pub fn reopen(snapshot: ProcessContractHostSnapshotV1) -> Self {
        Self::new(
            ProcessClaimJournalMemoryV1::reopen(snapshot.journal),
            snapshot.target,
            snapshot.clock_seed,
        )
    }

    /// Dispatches one validated intent through the outer admission's sole effect authority.
    pub fn dispatch(
        &mut self,
        intent: ValidatedProcessIntentV1,
        admission: &EffectAdmission,
    ) -> Result<ProcessHostOutcomeV1, ProcessContractErrorV1> {
        self.clock.reset();
        let outcome = ProcessOrchestratorV1::new().dispatch(
            intent,
            admission,
            &mut self.journal,
            &self.platform,
            &self.control,
            &mut self.output,
            &self.clock,
            &self.cancellation,
        )?;
        Ok(match outcome {
            ProcessDispatchOutcomeV1::Denied => ProcessHostOutcomeV1::Denied,
            ProcessDispatchOutcomeV1::State(state) => ProcessHostOutcomeV1::State(state),
            ProcessDispatchOutcomeV1::Terminal(result) => ProcessHostOutcomeV1::Terminal(result),
        })
    }
}

struct HostClock {
    seed: u64,
    next: Cell<u64>,
}

impl HostClock {
    const fn new(seed: u64) -> Self {
        Self {
            seed,
            next: Cell::new(seed),
        }
    }

    fn reset(&self) {
        self.next.set(self.seed);
    }
}

impl ProcessMonotonicClockV1 for HostClock {
    fn now_ticks(&self) -> u64 {
        let tick = self.next.get();
        self.next.set(tick.saturating_add(1));
        tick
    }
}

struct NeverCancelled;

impl ProcessCancellationTokenV1 for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct HostControl;

impl ProcessControlPortV1 for HostControl {
    fn request_graceful(
        &self,
        _: &ProcessLifecycleBindingV1,
    ) -> Result<(), ProcessPlatformFailure> {
        Err(not_qualified())
    }

    fn wait_for_grace(
        &self,
        _: &ProcessLifecycleBindingV1,
        _: MonotonicDeadline,
    ) -> Result<Option<ProcessTerminalEvidenceV1>, ProcessPlatformFailure> {
        Err(not_qualified())
    }

    fn observe_terminal(
        &self,
        _: &ProcessLifecycleBindingV1,
        _: MonotonicDeadline,
    ) -> Result<Option<ProcessTerminalEvidenceV1>, ProcessPlatformFailure> {
        Err(not_qualified())
    }
}

struct HostOutput;

impl ProcessOutputSourcePortV1 for HostOutput {
    fn next_bounded(
        &mut self,
        _: ProcessOutputReadBudgetV1,
    ) -> Result<ProcessOutputSourceEventV1, ProcessOutputSourceErrorV1> {
        Err(ProcessOutputSourceErrorV1::Closed)
    }

    fn stop_capture(
        &mut self,
        _: ProcessOutputStopReasonV1,
    ) -> Result<ProcessOutputStopEvidenceV1, ProcessOutputSourceErrorV1> {
        Ok(ProcessOutputStopEvidenceV1::new(false, false))
    }
}

const fn not_qualified() -> ProcessPlatformFailure {
    ProcessPlatformFailure::Disposition(ProcessStubDisposition::NotQualified)
}
