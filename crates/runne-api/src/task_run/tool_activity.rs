//! Bounded, runtime-scanned tool observations for authenticated clients.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskRunToolActivityV1 {
    pub task_run_id: String,
    pub workspace_id: String,
    pub entries: Vec<ToolActivityEntryV1>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolActivityEntryV1 {
    pub invocation_id: String,
    pub tool_name: String,
    pub target: String,
    pub state: String,
    pub result_text: Option<String>,
    pub truncated: bool,
}
