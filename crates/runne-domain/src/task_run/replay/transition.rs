use super::super::*;

include!("transition/lifecycle.rs");
include!("transition/loop.rs");
include!("transition/retry.rs");
include!("transition/checkpoint.rs");

impl TaskRun {
    /// Core transition table — dispatch an event to its focused transition group.
    pub fn apply_payload(&mut self, payload: &TaskRunEvent) -> Result<(), DomainError> {
        match payload {
            TaskRunEvent::TaskRunCreated
            | TaskRunEvent::TaskRunSubmitted { .. }
            | TaskRunEvent::TaskRunQueued
            | TaskRunEvent::TaskRunAdmitted
            | TaskRunEvent::AttemptStarted { .. }
            | TaskRunEvent::WaitStarted
            | TaskRunEvent::Resumed
            | TaskRunEvent::RetryStarted { .. }
            | TaskRunEvent::RetryCompleted { .. }
            | TaskRunEvent::CheckpointStarted
            | TaskRunEvent::CheckpointCommitted
            | TaskRunEvent::CancellationRequested
            | TaskRunEvent::CancellationCompleted
            | TaskRunEvent::TaskRunCompleted { .. }
            | TaskRunEvent::TaskRunFailed { .. }
            | TaskRunEvent::BudgetExhausted
            | TaskRunEvent::PolicyDenied
            | TaskRunEvent::ReconciliationStarted
            | TaskRunEvent::Reconciled
            | TaskRunEvent::Unrecoverable
            | TaskRunEvent::TaskRunCancelled => self.apply_lifecycle_payload(payload),
            TaskRunEvent::LoopCycleStarted { .. }
            | TaskRunEvent::ContextCommitted { .. }
            | TaskRunEvent::PlanCommitted { .. }
            | TaskRunEvent::StepOutcomeRecorded { .. }
            | TaskRunEvent::LoopCycleCompleted { .. }
            | TaskRunEvent::NextCycleCreated { .. } => self.apply_loop_payload(payload),
            TaskRunEvent::RetryScheduled { .. }
            | TaskRunEvent::ActivateScheduledRetryAttempt { .. }
            | TaskRunEvent::RecoveryResumeStarted { .. } => self.apply_retry_payload(payload),
            TaskRunEvent::LoopCheckpointStarted { .. }
            | TaskRunEvent::LoopCheckpointRecorded { .. }
            | TaskRunEvent::LoopCheckpointCommitted { .. }
            | TaskRunEvent::LoopWakeAccepted { .. } => self.apply_checkpoint_payload(payload),
        }
    }
}
