use reqwest::{Response, header::CACHE_CONTROL};

#[path = "reconciliation/correlation.rs"]
mod reconciliation_correlation;
#[path = "reconciliation/types.rs"]
mod reconciliation_types;
#[path = "reconciliation/wire.rs"]
mod reconciliation_wire;

pub use reconciliation_types::{
    CommandReconciliationDisposition, CommandReconciliationOutcome,
    ConversationGenerationFailureReason, ConversationTextRejection,
};
use reconciliation_correlation::correlate;
use reconciliation_wire::ReconciliationResponse;

const MAXIMUM_RECONCILIATION_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_RECONCILIATION_ERROR_BYTES: usize = 8 * 1024;

/// One validated, immutable reconciliation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandReconciliationRequest {
    identity: CommandIdentity,
    witness: CommandReconciliationWitness,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    tag = "operation",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum CommandReconciliationWitness {
    CreateProject { project_id: CanonicalId, display_name: String },
    ArchiveProject { project_id: CanonicalId, expected_version: u64 },
    DeleteProject { project_id: CanonicalId, expected_version: u64 },
    RenameProject { project_id: CanonicalId, expected_version: u64, display_name: String },
    CreateWorkspace { workspace_id: CanonicalId, project_id: CanonicalId, display_name: String },
    BindWorkspaceRoot { workspace_id: CanonicalId, expected_version: u64, admission_digest: String },
    OpenWorkspace { workspace_id: CanonicalId, expected_version: u64 },
    CreateConversation { conversation_id: CanonicalId, workspace_id: CanonicalId },
    GenerateConversationText { conversation_id: CanonicalId, expected_version: u64, text: String },
    CancelTaskRun { task_run_id: CanonicalId, expected_version: u64 },
    ApprovalDecision {
        approval_id: CanonicalId,
        expected_version: u64,
        decision: ApprovalDecisionDto,
        action_digest: String,
        policy_revision: u64,
        renderer_generation: u64,
    },
}

impl CommandReconciliationRequest {
    /// Builds a validated create-project reconciliation witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the display name is invalid.
    pub fn create_project(identity: CommandIdentity, project_id: CanonicalId, name: impl Into<String>) -> Result<Self, RuntimeApiError> {
        Ok(Self { identity, witness: CommandReconciliationWitness::CreateProject { project_id, display_name: reconciliation_display_name(name.into())? } })
    }
    /// Builds an archive-project witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the expected version is zero.
    pub fn archive_project(identity: CommandIdentity, project_id: CanonicalId, expected_version: u64) -> Result<Self, RuntimeApiError> {
        Ok(Self { identity, witness: CommandReconciliationWitness::ArchiveProject { project_id, expected_version: version(expected_version)? } })
    }
    /// Builds a delete-project witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the expected version is zero.
    pub fn delete_project(identity: CommandIdentity, project_id: CanonicalId, expected_version: u64) -> Result<Self, RuntimeApiError> {
        Ok(Self { identity, witness: CommandReconciliationWitness::DeleteProject { project_id, expected_version: version(expected_version)? } })
    }
    /// Builds a validated project-rename reconciliation witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` for a zero version or invalid display name.
    pub fn rename_project(identity: CommandIdentity, project_id: CanonicalId, expected_version: u64, name: impl Into<String>) -> Result<Self, RuntimeApiError> {
        Ok(Self { identity, witness: CommandReconciliationWitness::RenameProject { project_id, expected_version: version(expected_version)?, display_name: reconciliation_display_name(name.into())? } })
    }
    /// Builds a validated create-workspace reconciliation witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the display name is invalid.
    pub fn create_workspace(identity: CommandIdentity, workspace_id: CanonicalId, project_id: CanonicalId, name: impl Into<String>) -> Result<Self, RuntimeApiError> {
        Ok(Self { identity, witness: CommandReconciliationWitness::CreateWorkspace { workspace_id, project_id, display_name: reconciliation_display_name(name.into())? } })
    }
    /// Builds a root-binding witness without carrying root authority.
    ///
    /// # Errors
    /// Returns `InvalidRequest` for a zero version or non-canonical digest.
    pub fn bind_workspace_root(identity: CommandIdentity, workspace_id: CanonicalId, expected_version: u64, admission_digest: impl Into<String>) -> Result<Self, RuntimeApiError> {
        let admission_digest = admission_digest.into();
        if admission_digest.len() != 64 || !admission_digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) { return Err(invalid_request()); }
        Ok(Self { identity, witness: CommandReconciliationWitness::BindWorkspaceRoot { workspace_id, expected_version: version(expected_version)?, admission_digest } })
    }
    /// Builds an open-workspace witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the expected version is zero.
    pub fn open_workspace(identity: CommandIdentity, workspace_id: CanonicalId, expected_version: u64) -> Result<Self, RuntimeApiError> {
        Ok(Self { identity, witness: CommandReconciliationWitness::OpenWorkspace { workspace_id, expected_version: version(expected_version)? } })
    }
    #[must_use]
    pub const fn create_conversation(identity: CommandIdentity, conversation_id: CanonicalId, workspace_id: CanonicalId) -> Self {
        Self { identity, witness: CommandReconciliationWitness::CreateConversation { conversation_id, workspace_id } }
    }
    /// Builds a validated text-generation reconciliation witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` for a zero version or invalid message text.
    pub fn generate_conversation_text(identity: CommandIdentity, conversation_id: CanonicalId, expected_version: u64, text: impl Into<String>) -> Result<Self, RuntimeApiError> {
        let text = text.into(); validate_message_text(&text)?;
        Ok(Self { identity, witness: CommandReconciliationWitness::GenerateConversationText { conversation_id, expected_version: version(expected_version)?, text } })
    }
    #[must_use]
    pub const fn cancel_task_run(identity: CommandIdentity, task_run_id: CanonicalId, expected_version: u64) -> Self {
        Self { identity, witness: CommandReconciliationWitness::CancelTaskRun { task_run_id, expected_version } }
    }

    /// Builds a policy-bound approval decision reconciliation witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when a version is zero or the digest is empty.
    pub fn approval_decision(
        identity: CommandIdentity,
        approval_id: CanonicalId,
        expected_version: u64,
        decision: ApprovalDecisionDto,
        action_digest: [u8; 32],
        policy_revision: u64,
        renderer_generation: u64,
    ) -> Result<Self, RuntimeApiError> {
        if expected_version == 0
            || policy_revision == 0
            || renderer_generation == 0
            || action_digest == [0; 32]
        {
            return Err(invalid_request());
        }
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::ApprovalDecision {
                approval_id,
                expected_version,
                decision,
                action_digest: hex::encode(action_digest),
                policy_revision,
                renderer_generation,
            },
        })
    }
}

impl AuthenticatedRuntimeClient {
    /// Observes one command receipt without issuing a mutation or snapshot read.
    ///
    /// # Errors
    /// Returns a closed transport failure or `InvalidResponse` for an invalid observation.
    pub async fn reconcile_command(&self, request: CommandReconciliationRequest) -> Result<CommandReconciliationDisposition, RuntimeApiError> {
        let body = serde_json::to_vec(&request.witness).map_err(|_| invalid_request())?;
        let response = self.command_request(self.http_client().post(self.url("/v1/commands/reconcile")), &request.identity)?
            .header(CONTENT_TYPE, "application/json").body(body).send().await.map_err(map_transport)?;
        let cache_control: Vec<_> = response.headers().get_all(CACHE_CONTROL).iter().collect();
        if cache_control.len() != 1 || cache_control[0].as_bytes() != b"no-store" { return Err(invalid_response()); }
        if response.status().as_u16() != 200 { return Err(read_reconciliation_error(response).await); }
        let body = read_bounded(response, MAXIMUM_RECONCILIATION_RESPONSE_BYTES).await.map_err(|_| invalid_response())?;
        match serde_json::from_slice::<ReconciliationResponse>(&body).map_err(|_| invalid_response())? {
            ReconciliationResponse::NotCommittedRetryable => Ok(CommandReconciliationDisposition::NotCommittedRetryable),
            ReconciliationResponse::Indeterminate => Ok(CommandReconciliationDisposition::Indeterminate),
            ReconciliationResponse::DurablyRecorded { outcome } => Ok(CommandReconciliationDisposition::DurablyRecorded(correlate(&request.witness, outcome)?)),
        }
    }
}

fn version(value: u64) -> Result<u64, RuntimeApiError> { (value != 0).then_some(value).ok_or_else(invalid_request) }
fn reconciliation_display_name(value: String) -> Result<String, RuntimeApiError> {
    runne_api::ProjectWorkspaceDisplayNameInput::new(value.clone())
        .map(|_| value)
        .map_err(|_| invalid_request())
}
const fn invalid_request() -> RuntimeApiError { RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest) }
const fn invalid_response() -> RuntimeApiError { RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse) }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReconciliationErrorWire { code: String, request_id: String }

async fn read_reconciliation_error(response: Response) -> RuntimeApiError {
    let status = response.status().as_u16();
    let request_ids: Vec<_> = response.headers().get_all("x-request-id").iter().collect();
    let request_id = (request_ids.len() == 1).then(|| request_ids[0].to_str().ok()).flatten()
        .filter(|value| CanonicalId::parse(value).is_ok()).map(str::to_owned);
    let Ok(body) = read_bounded(response, MAXIMUM_RECONCILIATION_ERROR_BYTES).await else { return invalid_response(); };
    let Ok(error) = serde_json::from_slice::<ReconciliationErrorWire>(&body) else { return invalid_response(); };
    if request_id.as_deref() != Some(error.request_id.as_str()) || CanonicalId::parse(&error.request_id).is_err() { return invalid_response(); }
    let kind = match (status, error.code.as_str()) {
        (409, "command_conflict") => RuntimeApiErrorKind::Conflict,
        (503, "runtime_backpressure") => RuntimeApiErrorKind::Backpressure,
        (503, "runtime_unavailable") => RuntimeApiErrorKind::Unavailable,
        _ => return invalid_response(),
    };
    RuntimeApiError { kind, request_id: Some(error.request_id) }
}
