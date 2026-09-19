//! TaskRun aggregate — lifecycle state machine, events, transition table.
//!
//! The TaskRun is the core aggregate: it tracks execution state,
//! attempt history, and terminal outcomes.

use crate::agent_loop::{
    ActiveLoopCycle, CompletedCycleRef, CycleHistoryEntry, LoopCheckpointBody, LoopCycleState,
    LoopDisposition, PendingLoopCheckpoint, PendingLoopWait, PendingRetry, PendingSuccessorCycle,
    StepOutcomeRecord, StepOutcomeRef, StepOutcomeType, WakeEvidenceRef,
};
use crate::command::{CreateTaskRun, SubmitTaskRun, TaskRunCommand, TerminalResult};
use crate::context::ContextManifestRef;
use crate::error::{DomainError, LoopInvariantViolation};
use crate::event::{AggregateType, DomainEventDraft, EventEnvelope, Sensitivity};
use crate::id::{AggregateId, AttemptId, CheckpointId, CycleId, IntegrityDigest, TaskRunId};
use crate::plan::PlanRevisionRef;
use crate::recovery::{ReconciliationResultRef, ReconciliationStatus};
use crate::reference::{BudgetReservationRef, CheckpointRef};
use crate::verification::PlanEvaluationResult;
use std::fmt;

mod commands;
mod replay;
mod snapshot;
#[cfg(test)]
mod tests;
mod types;
mod validation;

pub use snapshot::{TaskRunSnapshotError, TaskRunSnapshotV1};
pub use types::{TaskRunEvent, TaskRunEventKind, TaskRunState};

// ── TaskRun aggregate ──────────────────────────────────────────────────────

/// The TaskRun aggregate root — tracks execution lifecycle.
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRun {
    /// The aggregate identity.
    id: TaskRunId,
    /// Current state.
    state: TaskRunState,
    /// The currently active attempt, if any.
    active_attempt: Option<AttemptId>,
    /// All known attempt IDs (ever).
    attempt_history: Vec<AttemptId>,
    /// Terminal result, if the task run has completed or failed.
    terminal_result: Option<TerminalResult>,
    /// Currently active loop cycle.
    active_cycle: Option<ActiveLoopCycle>,
    /// Last completed loop cycle.
    last_completed_cycle: Option<CompletedCycleRef>,
    /// Exact successor reservation.
    pending_successor: Option<PendingSuccessorCycle>,
    /// Exact wait condition pending wake evidence.
    pending_loop_wait: Option<PendingLoopWait>,
    /// Retry scheduled but not yet activated.
    pending_retry: Option<PendingRetry>,
    /// Loop checkpoint batch in progress.
    pending_loop_checkpoint: Option<PendingLoopCheckpoint>,
    /// Globally unique cycle history for this task run.
    cycle_history: Vec<CycleHistoryEntry>,
    /// Monotonic recovery generation.
    recovery_generation: u64,
}

impl fmt::Debug for TaskRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskRun")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("recovery_generation", &self.recovery_generation)
            .field("redacted", &true)
            .finish()
    }
}

impl TaskRun {
    /// Return the task run ID.
    pub fn id(&self) -> &TaskRunId {
        &self.id
    }

    /// Return the current state.
    pub fn state(&self) -> TaskRunState {
        self.state
    }

    /// Return the active attempt ID, if any.
    pub fn active_attempt(&self) -> Option<&AttemptId> {
        self.active_attempt.as_ref()
    }

    /// Return the attempt history.
    pub fn attempt_history(&self) -> &[AttemptId] {
        &self.attempt_history
    }

    /// Return the terminal result, if any.
    pub fn terminal_result(&self) -> Option<&TerminalResult> {
        self.terminal_result.as_ref()
    }

    /// Return the active loop cycle projection.
    pub fn active_cycle(&self) -> Option<&ActiveLoopCycle> {
        self.active_cycle.as_ref()
    }

    /// Return the last completed loop cycle projection.
    pub fn last_completed_cycle(&self) -> Option<&CompletedCycleRef> {
        self.last_completed_cycle.as_ref()
    }

    /// Return the pending successor reservation.
    pub fn pending_successor(&self) -> Option<&PendingSuccessorCycle> {
        self.pending_successor.as_ref()
    }

    /// Return the pending loop wait.
    pub fn pending_loop_wait(&self) -> Option<&PendingLoopWait> {
        self.pending_loop_wait.as_ref()
    }

    /// Return the pending retry.
    pub fn pending_retry(&self) -> Option<&PendingRetry> {
        self.pending_retry.as_ref()
    }

    /// Return the pending loop checkpoint.
    pub fn pending_loop_checkpoint(&self) -> Option<&PendingLoopCheckpoint> {
        self.pending_loop_checkpoint.as_ref()
    }

    /// Return all accepted cycle identities.
    pub fn cycle_history(&self) -> &[CycleHistoryEntry] {
        &self.cycle_history
    }

    /// Return the current recovery generation.
    pub fn recovery_generation(&self) -> u64 {
        self.recovery_generation
    }
}
