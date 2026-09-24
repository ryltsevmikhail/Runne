use runne_domain::id::TaskRunId;

use super::{TaskRunHostError, TaskRunSnapshot};

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
}
