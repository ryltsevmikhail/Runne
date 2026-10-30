use runne_domain::id::TaskRunId;

use super::{TaskRunEffectsV1, TaskRunHostError, TaskRunSnapshot};

/// Runtime host boundary for canonical non-mutating TaskRun queries.
pub trait TaskRunQueryHostPort: Send + Sync {
    /// Reconstructs one TaskRun from its committed stream.
    fn get_task_run(
        &self,
        taskrun_id: TaskRunId,
    ) -> impl std::future::Future<Output = Result<TaskRunSnapshot, TaskRunHostError>> + Send;

    /// Reconstructs every committed TaskRun for bounded lifecycle decisions.
    fn list_task_runs(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<TaskRunSnapshot>, TaskRunHostError>> + Send
    {
        async { Err(TaskRunHostError::Unavailable) }
    }

    /// Reads bounded tool activity only after principal/workspace authorization.
    fn get_task_run_tool_activity(
        &self,
        _principal: crate::ApiPrincipalId,
        _taskrun_id: TaskRunId,
    ) -> impl std::future::Future<Output = Result<super::TaskRunToolActivityV1, TaskRunHostError>> + Send
    {
        async { Err(TaskRunHostError::Unavailable) }
    }

    /// Reads factual local/remote effect evidence in one consistent store view.
    /// Hosts without the versioned effect projection fail closed.
    fn get_task_run_effects(
        &self,
        _taskrun_id: TaskRunId,
    ) -> impl std::future::Future<Output = Result<TaskRunEffectsV1, TaskRunHostError>> + Send {
        async { Err(TaskRunHostError::Unavailable) }
    }
}
