const fn task_run_state(state: TaskRunState) -> TaskRunProjectionState {
    match state {
        TaskRunState::Created => TaskRunProjectionState::Created,
        TaskRunState::Queued => TaskRunProjectionState::Queued,
        TaskRunState::Admitted => TaskRunProjectionState::Admitted,
        TaskRunState::Running => TaskRunProjectionState::Running,
        TaskRunState::Waiting => TaskRunProjectionState::Waiting,
        TaskRunState::Retrying => TaskRunProjectionState::Retrying,
        TaskRunState::Checkpointing => TaskRunProjectionState::Checkpointing,
        TaskRunState::Cancelling => TaskRunProjectionState::Cancelling,
        TaskRunState::Reconciling => TaskRunProjectionState::Reconciling,
        TaskRunState::Succeeded => TaskRunProjectionState::Succeeded,
        TaskRunState::Failed => TaskRunProjectionState::Failed,
        TaskRunState::Cancelled => TaskRunProjectionState::Cancelled,
        TaskRunState::BudgetExhausted => TaskRunProjectionState::BudgetExhausted,
        TaskRunState::PolicyDenied => TaskRunProjectionState::PolicyDenied,
        TaskRunState::Unrecoverable => TaskRunProjectionState::Unrecoverable,
    }
}

const fn task_run_terminal(state: TaskRunState) -> Option<TaskRunTerminalDisposition> {
    match state {
        TaskRunState::Succeeded => Some(TaskRunTerminalDisposition::Success),
        TaskRunState::Failed => Some(TaskRunTerminalDisposition::Failure),
        TaskRunState::Cancelled => Some(TaskRunTerminalDisposition::Cancelled),
        TaskRunState::BudgetExhausted => Some(TaskRunTerminalDisposition::BudgetExhausted),
        TaskRunState::PolicyDenied => Some(TaskRunTerminalDisposition::PolicyDenied),
        TaskRunState::Unrecoverable => Some(TaskRunTerminalDisposition::Unrecoverable),
        _ => None,
    }
}
