#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapState {
    pub theme: String,
    pub runtime_mode: RuntimeMode,
    pub runtime: RuntimeAvailability,
    pub runtime_lifecycle: RuntimeLifecycleStatus,
    pub runtime_failure: Option<RuntimeFailureCode>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsSnapshot {
    pub app_version: String,
    pub platform: String,
    pub database_schema_version: u32,
    pub database_generation: u64,
    pub project_count: u64,
    pub runtime_mode: RuntimeMode,
    pub runtime: RuntimeAvailability,
    pub runtime_lifecycle: RuntimeLifecycleStatus,
    pub runtime_failure: Option<RuntimeFailureCode>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDeviceSnapshot {
    pub connection: RuntimeAvailability,
    pub authenticated: bool,
    pub runtime_version: Option<String>,
    pub launch_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSummary {
    pub project_id: String,
    pub workspace_id: String,
    pub display_name: String,
    pub last_opened_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMessageSummary {
    pub message_id: String,
    pub role: String,
    pub task_run_id: String,
    pub attempt_id: String,
    pub text: String,
    pub committed_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationSnapshot {
    pub conversation_id: String,
    pub projection_revision: u64,
    pub stream_version: u64,
    pub messages: Vec<ConversationMessageSummary>,
    pub recovery: ConversationRecoveryDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationRecoveryDisposition {
    Live,
    Reconnecting,
    Incompatible,
    Revoked,
    ResyncRequired,
    Fatal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationTimelineUpdate {
    pub conversation_id: String,
    pub projection_revision: u64,
    pub stream_version: u64,
    pub message: Option<ConversationMessageSummary>,
    pub recovery: ConversationRecoveryDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskRunTimelineEntry {
    pub event_id: String,
    pub sequence: u64,
    pub committed_at: i64,
    pub kind: runne_runtime_client::TaskRunTimelineKind,
    pub attempt_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRunTerminalDisposition {
    Success,
    Failure,
    Cancelled,
    BudgetExhausted,
    PolicyDenied,
    Unrecoverable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRunProjectionState {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRunRecoveryDisposition {
    Live,
    Reconnecting,
    Incompatible,
    Revoked,
    ResyncRequired,
    Fatal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskRunTimelineSnapshot {
    pub task_run_id: String,
    pub projection_revision: u64,
    pub stream_version: u64,
    pub state: TaskRunProjectionState,
    pub active_attempt_id: Option<String>,
    pub terminal: Option<TaskRunTerminalDisposition>,
    pub entries: Vec<TaskRunTimelineEntry>,
    pub recovery: TaskRunRecoveryDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskRunTimelineUpdate {
    pub task_run_id: String,
    pub projection_revision: u64,
    pub stream_version: u64,
    pub entry: Option<TaskRunTimelineEntry>,
    pub recovery: TaskRunRecoveryDisposition,
}

impl From<RecentRoot> for ProjectSummary {
    fn from(project: RecentRoot) -> Self {
        Self {
            project_id: project.project_id().to_owned(),
            workspace_id: project.workspace_id().to_owned(),
            display_name: project.display_name().to_owned(),
            last_opened_at: project.last_opened_at(),
        }
    }
}
