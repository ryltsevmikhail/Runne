const MAXIMUM_TASK_RUN_FAILURE_REASON_BYTES: usize = 4 * 1024;

/// Closed authoritative `TaskRun` lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskRunState {
    Created,
    Queued,
    Admitted,
    Running,
    Waiting,
    Retrying,
    Checkpointing,
    Cancelling,
    Reconciling,
    Succeeded,
    Failed,
    Cancelled,
    BudgetExhausted,
    PolicyDenied,
    Unrecoverable,
}

/// Closed terminal result carried by a terminal `TaskRun`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskRunTerminalResult {
    Success,
    Failure { reason: String },
}

/// Validated authoritative `TaskRun` snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRunSnapshot {
    task_run_id: CanonicalId,
    state: TaskRunState,
    stream_version: u64,
    active_attempt_id: Option<CanonicalId>,
    terminal_result: Option<TaskRunTerminalResult>,
}

/// Runtime acknowledgement that a cancellation request was durably accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskRunCancellationAcknowledgement {
    task_run_id: CanonicalId,
    stream_version: u64,
}

impl TaskRunCancellationAcknowledgement {
    pub(crate) const fn observed(task_run_id: CanonicalId, stream_version: u64) -> Self {
        Self { task_run_id, stream_version }
    }

    #[must_use]
    pub const fn task_run_id(self) -> CanonicalId {
        self.task_run_id
    }

    #[must_use]
    pub const fn stream_version(self) -> u64 {
        self.stream_version
    }
}

impl TaskRunSnapshot {
    #[must_use]
    pub const fn task_run_id(&self) -> CanonicalId {
        self.task_run_id
    }

    #[must_use]
    pub const fn state(&self) -> TaskRunState {
        self.state
    }

    #[must_use]
    pub const fn stream_version(&self) -> u64 {
        self.stream_version
    }

    #[must_use]
    pub const fn active_attempt_id(&self) -> Option<CanonicalId> {
        self.active_attempt_id
    }

    #[must_use]
    pub const fn terminal_result(&self) -> Option<&TaskRunTerminalResult> {
        self.terminal_result.as_ref()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TaskRunSnapshotWire {
    task_run_id: CanonicalId,
    state: TaskRunStateWire,
    stream_version: u64,
    #[serde(default)]
    active_attempt_id: PresentOption<CanonicalId>,
    #[serde(default)]
    terminal_result: PresentOption<TaskRunTerminalResultWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TaskRunCancellationAcknowledgementWire {
    task_run_id: CanonicalId,
    stream_version: u64,
    transition: String,
    attempt_id: Option<CanonicalId>,
    terminal_result: Option<TaskRunTerminalResultWire>,
}

impl TryFrom<TaskRunCancellationAcknowledgementWire>
    for TaskRunCancellationAcknowledgement
{
    type Error = RuntimeApiError;

    fn try_from(wire: TaskRunCancellationAcknowledgementWire) -> Result<Self, Self::Error> {
        if wire.stream_version == 0
            || wire.transition != "cancellation_requested"
            || wire.attempt_id.is_some()
            || wire.terminal_result.is_some()
        {
            return Err(invalid_task_run_response());
        }
        Ok(Self {
            task_run_id: wire.task_run_id,
            stream_version: wire.stream_version,
        })
    }
}

#[derive(Default)]
enum PresentOption<T> {
    #[default]
    Missing,
    Present(Option<T>),
}

impl<'de, T> Deserialize<'de> for PresentOption<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum TaskRunStateWire {
    Created,
    Queued,
    Admitted,
    Running,
    Waiting,
    Retrying,
    Checkpointing,
    Cancelling,
    Reconciling,
    Succeeded,
    Failed,
    Cancelled,
    BudgetExhausted,
    PolicyDenied,
    Unrecoverable,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum TaskRunTerminalResultWire {
    Success,
    Failure { reason: String },
}

impl TryFrom<TaskRunSnapshotWire> for TaskRunSnapshot {
    type Error = RuntimeApiError;

    fn try_from(wire: TaskRunSnapshotWire) -> Result<Self, Self::Error> {
        if wire.stream_version == 0 {
            return Err(invalid_task_run_response());
        }
        let PresentOption::Present(active_attempt_id) = wire.active_attempt_id else {
            return Err(invalid_task_run_response());
        };
        let PresentOption::Present(terminal_result_wire) = wire.terminal_result else {
            return Err(invalid_task_run_response());
        };
        let state = match wire.state {
            TaskRunStateWire::Created => TaskRunState::Created,
            TaskRunStateWire::Queued => TaskRunState::Queued,
            TaskRunStateWire::Admitted => TaskRunState::Admitted,
            TaskRunStateWire::Running => TaskRunState::Running,
            TaskRunStateWire::Waiting => TaskRunState::Waiting,
            TaskRunStateWire::Retrying => TaskRunState::Retrying,
            TaskRunStateWire::Checkpointing => TaskRunState::Checkpointing,
            TaskRunStateWire::Cancelling => TaskRunState::Cancelling,
            TaskRunStateWire::Reconciling => TaskRunState::Reconciling,
            TaskRunStateWire::Succeeded => TaskRunState::Succeeded,
            TaskRunStateWire::Failed => TaskRunState::Failed,
            TaskRunStateWire::Cancelled => TaskRunState::Cancelled,
            TaskRunStateWire::BudgetExhausted => TaskRunState::BudgetExhausted,
            TaskRunStateWire::PolicyDenied => TaskRunState::PolicyDenied,
            TaskRunStateWire::Unrecoverable => TaskRunState::Unrecoverable,
        };
        let terminal_result = terminal_result_wire
            .map(validate_terminal_result)
            .transpose()?;
        if !valid_task_run_snapshot(state, active_attempt_id, terminal_result.as_ref()) {
            return Err(invalid_task_run_response());
        }
        Ok(Self {
            task_run_id: wire.task_run_id,
            state,
            stream_version: wire.stream_version,
            active_attempt_id,
            terminal_result,
        })
    }
}

fn validate_terminal_result(
    result: TaskRunTerminalResultWire,
) -> Result<TaskRunTerminalResult, RuntimeApiError> {
    match result {
        TaskRunTerminalResultWire::Success => Ok(TaskRunTerminalResult::Success),
        TaskRunTerminalResultWire::Failure { reason }
            if !reason.is_empty() && reason.len() <= MAXIMUM_TASK_RUN_FAILURE_REASON_BYTES =>
        {
            Ok(TaskRunTerminalResult::Failure { reason })
        }
        TaskRunTerminalResultWire::Failure { .. } => Err(invalid_task_run_response()),
    }
}

const fn valid_task_run_snapshot(
    state: TaskRunState,
    active_attempt_id: Option<CanonicalId>,
    terminal_result: Option<&TaskRunTerminalResult>,
) -> bool {
    match state {
        TaskRunState::Running
        | TaskRunState::Waiting
        | TaskRunState::Retrying
        | TaskRunState::Checkpointing
        | TaskRunState::Reconciling => active_attempt_id.is_some() && terminal_result.is_none(),
        TaskRunState::Created
        | TaskRunState::Queued
        | TaskRunState::Admitted
        | TaskRunState::Failed
        | TaskRunState::Cancelled
        | TaskRunState::BudgetExhausted
        | TaskRunState::PolicyDenied
        | TaskRunState::Unrecoverable => {
            active_attempt_id.is_none() && terminal_result.is_none()
        }
        TaskRunState::Cancelling => terminal_result.is_none(),
        TaskRunState::Succeeded => active_attempt_id.is_none() && terminal_result.is_some(),
    }
}

const fn invalid_task_run_response() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse)
}
