use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StartBody {
    pub workspace_id: String,
    pub task_run_id: String,
    pub attempt_id: String,
    pub invocation_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StopBody {
    pub expected_version: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct OutputQuery {
    pub after_sequence: Option<u64>,
    pub limit: Option<u16>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SnapshotWire {
    pub process_id: String,
    pub invocation_id: String,
    pub workspace_id: String,
    pub state: &'static str,
    pub version: u64,
    pub next_output_sequence: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct OutputPageWire {
    pub chunks: Vec<OutputChunkWire>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct OutputChunkWire {
    pub sequence: u64,
    pub stream: &'static str,
    pub text: String,
}
