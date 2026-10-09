use runne_api::{ApprovalDecision, ApprovalDecisionAck, ApprovalSummary};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ApprovalListWire {
    pub items: Vec<ApprovalSummaryWire>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ApprovalSummaryWire {
    pub approval_id: String,
    pub task_run_id: String,
    pub attempt_id: Option<String>,
    pub invocation_id: String,
    pub action: String,
    pub resource: String,
    pub action_digest: String,
    pub policy_revision: u64,
    pub request_version: u64,
    pub approval_generation: u64,
    pub expires_at: i64,
    pub risk_summary: String,
    pub state: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DecisionBody {
    pub expected_version: u64,
    pub decision: String,
    pub action_digest: String,
    pub policy_revision: u64,
    pub renderer_generation: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DecisionAckWire {
    pub approval_id: String,
    pub task_run_id: String,
    pub new_version: u64,
    pub state: &'static str,
}

impl From<ApprovalSummary> for ApprovalSummaryWire {
    fn from(value: ApprovalSummary) -> Self {
        Self {
            approval_id: value.approval_id().to_string(),
            task_run_id: value.task_run_id().to_string(),
            attempt_id: value.attempt_id().map(|id| id.to_string()),
            invocation_id: value.invocation_id().to_string(),
            action: value.action().to_owned(),
            resource: value.resource().to_owned(),
            action_digest: hex::encode(value.action_digest()),
            policy_revision: value.policy_revision(),
            request_version: value.request_version(),
            approval_generation: value.approval_generation(),
            expires_at: value.expires_at(),
            risk_summary: value.risk_summary().to_owned(),
            state: value.state().as_str(),
        }
    }
}

impl From<ApprovalDecisionAck> for DecisionAckWire {
    fn from(value: ApprovalDecisionAck) -> Self {
        Self {
            approval_id: value.approval_id().to_string(),
            task_run_id: value.task_run_id().to_string(),
            new_version: value.new_version(),
            state: value.state().as_str(),
        }
    }
}

#[allow(dead_code)]
fn _decision_name(value: ApprovalDecision) -> &'static str {
    value.as_str()
}
