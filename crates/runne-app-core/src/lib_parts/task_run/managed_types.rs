#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedTaskRunAuthority {
    pub provider: ManagedTaskRunField,
    pub model: ManagedTaskRunField,
    pub policy: ManagedTaskRunField,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedTaskRunField {
    pub status: &'static str,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedTaskRunPreflight {
    pub status: &'static str,
    pub generation: Option<u64>,
    pub project_id: String,
    pub workspace_id: String,
    pub conversation_id: Option<String>,
    pub can_start: bool,
    pub start_unavailable_reason: Option<&'static str>,
    pub recovery_token: Option<String>,
    pub authority: ManagedTaskRunAuthority,
    pub draft_policy: ManagedTaskDraftPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedTaskDraftPolicy {
    ProtectedRestart,
    MemoryOnly,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedTaskRunItem {
    pub task_run_id: String,
    pub workspace_id: Option<String>,
    pub conversation_id: Option<String>,
    pub state: &'static str,
    pub terminal: Option<TaskRunTerminalDisposition>,
    pub stream_version: u64,
    pub active_attempt_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedTaskRunList {
    pub status: &'static str,
    pub task_runs: Vec<ManagedTaskRunItem>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedAttentionItem {
    pub approval_id: Option<String>,
    pub task_run_id: Option<String>,
    pub kind: &'static str,
    pub workspace_id: Option<String>,
    pub conversation_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedAttentionSnapshot {
    pub status: &'static str,
    pub complete: bool,
    pub items: Vec<ManagedAttentionItem>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedTaskRunStart {
    pub status: &'static str,
    pub task_run_id: Option<String>,
    pub stream_version: Option<u64>,
    pub recovery_token: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedTaskRunRecovery {
    pub status: &'static str,
    pub task_run_id: Option<String>,
    pub stream_version: Option<u64>,
    pub workspace_id: Option<String>,
    pub conversation_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedTaskRunIntent {
    runtime: replay::StableRuntimeIdentity,
    project_id: String,
    workspace_id: String,
    conversation_id: String,
    generation: u64,
    recovery_token: String,
}

const fn unavailable_managed_field() -> ManagedTaskRunField {
    ManagedTaskRunField {
        status: "unavailable",
        reason: "runtime_projection_missing",
    }
}

const fn task_run_state_name(state: runne_runtime_client::TaskRunState) -> &'static str {
    use runne_runtime_client::TaskRunState as State;
    match state {
        State::Created => "created",
        State::Queued => "queued",
        State::Admitted => "admitted",
        State::Running => "running",
        State::Waiting => "waiting",
        State::Retrying => "retrying",
        State::Checkpointing => "checkpointing",
        State::Cancelling => "cancelling",
        State::Reconciling => "reconciling",
        State::Succeeded => "succeeded",
        State::Failed => "failed",
        State::Cancelled => "cancelled",
        State::BudgetExhausted => "budget_exhausted",
        State::PolicyDenied => "policy_denied",
        State::Unrecoverable => "unrecoverable",
    }
}
