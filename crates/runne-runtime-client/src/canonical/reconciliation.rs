use reqwest::{Response, header::CACHE_CONTROL};

#[path = "reconciliation/correlation.rs"]
mod reconciliation_correlation;
#[path = "reconciliation/types.rs"]
mod reconciliation_types;
#[path = "reconciliation/wire.rs"]
mod reconciliation_wire;

use reconciliation_correlation::correlate;
pub use reconciliation_types::{
    CommandReconciliationDisposition, CommandReconciliationOutcome,
    ConversationGenerationFailureReason, ConversationTextRejection,
};
use reconciliation_wire::ReconciliationResponse;
#[path = "reconciliation/request_builders.rs"]
mod reconciliation_request_builders;
#[path = "reconciliation/request_builders_model.rs"]
mod reconciliation_request_builders_model;

const MAXIMUM_RECONCILIATION_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_RECONCILIATION_ERROR_BYTES: usize = 8 * 1024;

/// One validated, immutable reconciliation request.
#[derive(Clone, Eq, PartialEq)]
pub struct CommandReconciliationRequest {
    identity: CommandIdentity,
    witness: CommandReconciliationWitness,
}

impl std::fmt::Debug for CommandReconciliationRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandReconciliationRequest")
            .field("identity", &self.identity)
            .field("witness", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    tag = "operation",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum CommandReconciliationWitness {
    CreateProject {
        project_id: CanonicalId,
        display_name: String,
    },
    ArchiveProject {
        project_id: CanonicalId,
        expected_version: u64,
    },
    DeleteProject {
        project_id: CanonicalId,
        expected_version: u64,
    },
    RenameProject {
        project_id: CanonicalId,
        expected_version: u64,
        display_name: String,
    },
    CreateWorkspace {
        workspace_id: CanonicalId,
        project_id: CanonicalId,
        display_name: String,
    },
    BindWorkspaceRoot {
        workspace_id: CanonicalId,
        expected_version: u64,
        admission_digest: String,
    },
    OpenWorkspace {
        workspace_id: CanonicalId,
        expected_version: u64,
    },
    CreateConversation {
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
    },
    CreateTextOnlyConversation {
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
    },
    GenerateConversationText {
        conversation_id: CanonicalId,
        expected_version: u64,
        text: String,
    },
    CancelTaskRun {
        task_run_id: CanonicalId,
        expected_version: u64,
    },
    SupersedeUnknownTaskRun { predecessor_task_run_id: CanonicalId, expected_version: u64 },
    SubmitTaskRun {
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        #[serde(skip_serializing_if = "Option::is_none")]
        prompt: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        profile: Option<ReconciliationProfileWire>,
        #[serde(skip_serializing_if = "Option::is_none")]
        local_command: Option<ReconciliationLocalCommandWire>,
    },
    ApprovalDecision {
        approval_id: CanonicalId,
        expected_version: u64,
        decision: ApprovalDecisionDto,
        action_digest: String,
        policy_revision: u64,
        renderer_generation: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReconciliationProfileWire {
    profile_id: String,
    profile_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReconciliationLocalCommandWire {
    executable: ReconciliationExecutableWire,
    cwd: String,
    argv: Vec<String>,
    env: Vec<ReconciliationEnvironmentWire>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum ReconciliationExecutableWire {
    WorkspaceRelative(String),
    SystemProgram(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReconciliationEnvironmentWire {
    key: String,
    value: String,
}

impl AuthenticatedRuntimeClient {
    /// Observes one command receipt without issuing a mutation or snapshot read.
    ///
    /// # Errors
    /// Returns a closed transport failure or `InvalidResponse` for an invalid observation.
    pub async fn reconcile_command(
        &self,
        request: CommandReconciliationRequest,
    ) -> Result<CommandReconciliationDisposition, RuntimeApiError> {
        let body = serde_json::to_vec(&request.witness).map_err(|_| invalid_request())?;
        let response = self
            .command_request(
                self.http_client().post(self.url("/v1/commands/reconcile")),
                &request.identity,
            )?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        let cache_control: Vec<_> = response.headers().get_all(CACHE_CONTROL).iter().collect();
        if cache_control.len() != 1 || cache_control[0].as_bytes() != b"no-store" {
            return Err(invalid_response());
        }
        if response.status().as_u16() != 200 {
            return Err(read_reconciliation_error(response).await);
        }
        let body = read_bounded(response, MAXIMUM_RECONCILIATION_RESPONSE_BYTES)
            .await
            .map_err(|_| invalid_response())?;
        match serde_json::from_slice::<ReconciliationResponse>(&body)
            .map_err(|_| invalid_response())?
        {
            ReconciliationResponse::NotCommittedRetryable => {
                Ok(CommandReconciliationDisposition::NotCommittedRetryable)
            }
            ReconciliationResponse::Indeterminate => {
                Ok(CommandReconciliationDisposition::Indeterminate)
            }
            ReconciliationResponse::DurablyRecorded { outcome } => {
                Ok(CommandReconciliationDisposition::DurablyRecorded(
                    correlate(&request.witness, outcome)?,
                ))
            }
        }
    }
}

fn version(value: u64) -> Result<u64, RuntimeApiError> {
    (value != 0).then_some(value).ok_or_else(invalid_request)
}
fn reconciliation_display_name(value: String) -> Result<String, RuntimeApiError> {
    runne_api::ProjectWorkspaceDisplayNameInput::new(value.clone())
        .map(|_| value)
        .map_err(|_| invalid_request())
}
const fn invalid_request() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest)
}
const fn invalid_response() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReconciliationErrorWire {
    code: String,
    request_id: String,
}

async fn read_reconciliation_error(response: Response) -> RuntimeApiError {
    let status = response.status().as_u16();
    let request_ids: Vec<_> = response.headers().get_all("x-request-id").iter().collect();
    let request_id = (request_ids.len() == 1)
        .then(|| request_ids[0].to_str().ok())
        .flatten()
        .filter(|value| CanonicalId::parse(value).is_ok())
        .map(str::to_owned);
    let Ok(body) = read_bounded(response, MAXIMUM_RECONCILIATION_ERROR_BYTES).await else {
        return invalid_response();
    };
    let Ok(error) = serde_json::from_slice::<ReconciliationErrorWire>(&body) else {
        return invalid_response();
    };
    if request_id.as_deref() != Some(error.request_id.as_str())
        || CanonicalId::parse(&error.request_id).is_err()
    {
        return invalid_response();
    }
    let kind = match (status, error.code.as_str()) {
        (409, "command_conflict") => RuntimeApiErrorKind::Conflict,
        (503, "runtime_backpressure") => RuntimeApiErrorKind::Backpressure,
        (503, "runtime_unavailable") => RuntimeApiErrorKind::Unavailable,
        _ => return invalid_response(),
    };
    RuntimeApiError {
        kind,
        request_id: Some(error.request_id),
    }
}
