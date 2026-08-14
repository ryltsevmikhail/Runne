use super::TaskRun;
use crate::agent_loop::{
    ActiveLoopCycle, CompletedCycleRef, CycleHistoryEntry, PendingLoopCheckpoint, PendingLoopWait,
    PendingRetry, PendingSuccessorCycle,
};
use crate::command::TerminalResult;
use crate::id::{AttemptId, TaskRunId};
use crate::task_run::TaskRunState;
use std::fmt;

#[path = "snapshot/codec.rs"]
mod codec;
#[path = "snapshot/cycles.rs"]
mod cycles;
#[path = "snapshot/io.rs"]
mod io;
#[path = "snapshot/refs.rs"]
mod refs;
#[path = "snapshot/validation.rs"]
mod validation;

/// Immutable complete TaskRun projection accepted only through the closed codec.
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunSnapshotV1(TaskRun);

/// Failure while decoding or validating a closed TaskRun projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRunSnapshotError {
    InvalidEncoding,
    InvalidState,
}

impl fmt::Debug for TaskRunSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskRunSnapshotV1")
            .field("id", &self.id())
            .field("redacted", &true)
            .finish()
    }
}

impl TaskRunSnapshotV1 {
    /// Encodes exact current aggregate state without serializing event history.
    pub fn encode(&self) -> Result<Vec<u8>, TaskRunSnapshotError> {
        codec::encode(&self.0)
    }

    /// Decodes exact versioned projection and validates all cross-field invariants.
    pub fn decode(bytes: &[u8]) -> Result<Self, TaskRunSnapshotError> {
        Ok(Self(codec::decode(bytes)?))
    }

    /// Returns the bound aggregate identity.
    pub const fn id(&self) -> TaskRunId {
        self.0.id
    }

    /// Returns the closed lifecycle state without allowing aggregate restoration.
    pub const fn state(&self) -> TaskRunState {
        self.0.state
    }
    pub const fn active_attempt(&self) -> Option<&AttemptId> {
        self.0.active_attempt.as_ref()
    }
    pub fn attempt_history(&self) -> &[AttemptId] {
        &self.0.attempt_history
    }
    pub const fn terminal_result(&self) -> Option<&TerminalResult> {
        self.0.terminal_result.as_ref()
    }
    pub const fn active_cycle(&self) -> Option<&ActiveLoopCycle> {
        self.0.active_cycle.as_ref()
    }
    pub const fn last_completed_cycle(&self) -> Option<&CompletedCycleRef> {
        self.0.last_completed_cycle.as_ref()
    }
    pub const fn pending_successor(&self) -> Option<&PendingSuccessorCycle> {
        self.0.pending_successor.as_ref()
    }
    pub const fn pending_loop_wait(&self) -> Option<&PendingLoopWait> {
        self.0.pending_loop_wait.as_ref()
    }
    pub const fn pending_retry(&self) -> Option<&PendingRetry> {
        self.0.pending_retry.as_ref()
    }
    pub const fn pending_loop_checkpoint(&self) -> Option<&PendingLoopCheckpoint> {
        self.0.pending_loop_checkpoint.as_ref()
    }
    pub fn cycle_history(&self) -> &[CycleHistoryEntry] {
        &self.0.cycle_history
    }
    pub const fn recovery_generation(&self) -> u64 {
        self.0.recovery_generation
    }
}

impl TaskRun {
    /// Returns a complete closed projection suitable for an authenticated replay baseline.
    #[must_use]
    pub fn snapshot_v1(&self) -> TaskRunSnapshotV1 {
        TaskRunSnapshotV1(self.clone())
    }
}
