use runne_api::{
    CompleteTaskRunCommand, CreateTaskRunCommand, ExistingTaskRunCommand, SubmitTaskRunCommand,
    TaskRunCommandAck, TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError,
    TaskRunQueryHostPort, TaskRunSnapshot,
};
use runne_domain::id::TaskRunId;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(super) struct UnavailableTaskRunHost {
    pub(super) submissions: Option<Arc<Mutex<Vec<SubmitTaskRunCommand>>>>,
}

impl TaskRunCommandHostPort for UnavailableTaskRunHost {
    async fn create_task_run(
        &self,
        _: TaskRunCommandContext,
        _: CreateTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }

    async fn submit_task_run(
        &self,
        _: TaskRunCommandContext,
        command: SubmitTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        if let Some(submissions) = &self.submissions {
            submissions.lock().unwrap().push(command);
        }
        Err(TaskRunHostError::Unavailable)
    }

    async fn queue_task_run(
        &self,
        _: TaskRunCommandContext,
        _: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }

    async fn admit_task_run(
        &self,
        _: TaskRunCommandContext,
        _: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }

    async fn start_attempt(
        &self,
        _: TaskRunCommandContext,
        _: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }

    async fn complete_task_run(
        &self,
        _: TaskRunCommandContext,
        _: CompleteTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }
}

impl TaskRunQueryHostPort for UnavailableTaskRunHost {
    async fn get_task_run(&self, _: TaskRunId) -> Result<TaskRunSnapshot, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }
}
