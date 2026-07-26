//! Command input/output DTOs for the TaskRun service.
//!
//! These are the types visible to callers of [`crate::service::TaskRunService`].

use gocode_domain::command::TerminalResult;
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId, WorkspaceId};

/// Input for creating a new task run.
#[derive(Debug, Clone)]
pub struct CreateTaskRunInput {
    /// The conversation this task run belongs to.
    pub conversation_id: ConversationId,
    /// The workspace this task run belongs to.
    pub workspace_id: WorkspaceId,
}

/// Input for queuing a task run for admission.
#[derive(Debug, Clone)]
pub struct QueueTaskRunInput {
    /// The task run to queue.
    pub taskrun_id: TaskRunId,
    /// The version the caller expects (0 for initial queue after create).
    pub expected_version: u64,
}

/// Input for admitting a task run for execution.
#[derive(Debug, Clone)]
pub struct AdmitTaskRunInput {
    /// The task run to admit.
    pub taskrun_id: TaskRunId,
    /// The version the caller expects.
    pub expected_version: u64,
}

/// Input for starting a new execution attempt.
#[derive(Debug, Clone)]
pub struct StartAttemptInput {
    /// The task run to start an attempt on.
    pub taskrun_id: TaskRunId,
    /// The version the caller expects.
    pub expected_version: u64,
}

/// Input for completing a task run.
#[derive(Debug, Clone)]
pub struct CompleteTaskRunInput {
    /// The task run to complete.
    pub taskrun_id: TaskRunId,
    /// The terminal result (success or failure).
    pub result: TerminalResult,
    /// The version the caller expects.
    pub expected_version: u64,
}

/// The outcome of a successfully processed command.
///
/// Returned to the caller after the command is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    /// A task run was created.
    TaskRunCreated {
        /// The ID of the newly created task run.
        taskrun_id: TaskRunId,
        /// The new stream version (always 1).
        new_version: u64,
    },
    /// A task run was queued for admission.
    TaskRunQueued {
        /// The task run ID.
        taskrun_id: TaskRunId,
        /// The new stream version.
        new_version: u64,
    },
    /// A task run was admitted for execution.
    TaskRunAdmitted {
        /// The task run ID.
        taskrun_id: TaskRunId,
        /// The new stream version.
        new_version: u64,
    },
    /// A new attempt was started.
    AttemptStarted {
        /// The task run ID.
        taskrun_id: TaskRunId,
        /// The newly generated attempt ID.
        attempt_id: AttemptId,
        /// The new stream version.
        new_version: u64,
    },
    /// A task run was completed with a terminal result.
    TaskRunCompleted {
        /// The task run ID.
        taskrun_id: TaskRunId,
        /// The new stream version.
        new_version: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";

    #[test]
    fn test_command_outcome_clone_eq() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let c1 = CommandOutcome::TaskRunCreated {
            taskrun_id: tr_id,
            new_version: 1,
        };
        let c2 = c1.clone();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_command_outcome_attempt_started_holds_attempt_id() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let att_id: AttemptId = "018f2e3a-7000-7000-8000-000000000001".parse().unwrap();
        let outcome = CommandOutcome::AttemptStarted {
            taskrun_id: tr_id,
            attempt_id: att_id,
            new_version: 4,
        };
        if let CommandOutcome::AttemptStarted { attempt_id, .. } = &outcome {
            assert_eq!(*attempt_id, att_id);
        } else {
            panic!("expected AttemptStarted");
        }
    }
}
