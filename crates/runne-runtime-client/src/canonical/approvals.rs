/// Strict runtime-client projection for approval query and decision flows.
/// Capability required before approval data or decisions are exposed.
pub const APPROVALS_CAPABILITY_V1: &str = "approval.control.v1";
const MAX_APPROVAL_DISPLAY_BYTES: usize = 4096;

/// Closed approval lifecycle state safe for renderer projections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalStateDto {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

/// Decision accepted by the runtime approval command.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionDto {
    Approve,
    Deny,
}

/// Sanitized approval projection with no authority material or secret payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalSummaryDto {
    approval_id: CanonicalId,
    task_run_id: CanonicalId,
    attempt_id: Option<CanonicalId>,
    invocation_id: CanonicalId,
    action: String,
    resource: String,
    action_digest: [u8; 32],
    policy_revision: u64,
    request_version: u64,
    expires_at: i64,
    risk_summary: String,
    state: ApprovalStateDto,
}

impl ApprovalSummaryDto {
    #[must_use]
    pub const fn approval_id(&self) -> CanonicalId { self.approval_id }
    #[must_use]
    pub const fn task_run_id(&self) -> CanonicalId { self.task_run_id }
    #[must_use]
    pub const fn attempt_id(&self) -> Option<CanonicalId> { self.attempt_id }
    #[must_use]
    pub const fn invocation_id(&self) -> CanonicalId { self.invocation_id }
    #[must_use]
    pub fn action(&self) -> &str { &self.action }
    #[must_use]
    pub fn resource(&self) -> &str { &self.resource }
    #[must_use]
    pub const fn action_digest(&self) -> &[u8; 32] { &self.action_digest }
    #[must_use]
    pub const fn policy_revision(&self) -> u64 { self.policy_revision }
    #[must_use]
    pub const fn request_version(&self) -> u64 { self.request_version }
    #[must_use]
    pub const fn expires_at(&self) -> i64 { self.expires_at }
    #[must_use]
    pub fn risk_summary(&self) -> &str { &self.risk_summary }
    #[must_use]
    pub const fn state(&self) -> ApprovalStateDto { self.state }
    #[must_use]
    pub const fn requires_decision(&self) -> bool { matches!(self.state, ApprovalStateDto::Pending) }
}

/// Runtime command identity and approval binding for one decision attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalDecisionRequest {
    pub(crate) identity: CommandIdentity,
    approval_id: CanonicalId,
    expected_version: u64,
    decision: ApprovalDecisionDto,
    action_digest: [u8; 32],
    policy_revision: u64,
    renderer_generation: u64,
}

impl ApprovalDecisionRequest {
    /// Creates a request only when all replay-sensitive bindings are present.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when a version is zero or the digest is empty.
    pub fn new(
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
            approval_id,
            expected_version,
            decision,
            action_digest,
            policy_revision,
            renderer_generation,
        })
    }
}

/// Durable acknowledgement returned after runtime commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalDecisionAcknowledgementDto {
    approval_id: CanonicalId,
    task_run_id: CanonicalId,
    new_version: u64,
    state: ApprovalStateDto,
}

impl ApprovalDecisionAcknowledgementDto {
    pub(crate) const fn observed(
        approval_id: CanonicalId,
        task_run_id: CanonicalId,
        new_version: u64,
        state: ApprovalStateDto,
    ) -> Result<Self, RuntimeApiError> {
        if new_version == 0 || matches!(state, ApprovalStateDto::Pending) {
            return Err(invalid_response());
        }
        Ok(Self { approval_id, task_run_id, new_version, state })
    }

    #[must_use]
    pub const fn approval_id(self) -> CanonicalId { self.approval_id }
    #[must_use]
    pub const fn task_run_id(self) -> CanonicalId { self.task_run_id }
    #[must_use]
    pub const fn new_version(self) -> u64 { self.new_version }
    #[must_use]
    pub const fn state(self) -> ApprovalStateDto { self.state }
}

impl AuthenticatedRuntimeClient {
    /// Lists pending approvals authorized for this runtime session.
    ///
    /// # Errors
    /// Returns a closed transport, capability, or response-validation error.
    pub async fn list_pending_approvals(&self) -> Result<Vec<ApprovalSummaryDto>, RuntimeApiError> {
        require_capability(self, APPROVALS_CAPABILITY_V1)?;
        let response = self
            .authenticated_request(self.client.get(self.url("/v1/approvals")))?
            .send().await.map_err(map_transport)?;
        let wire: ApprovalListWire = read_success_json(response, &[200]).await?;
        wire.items.into_iter().map(TryInto::try_into).collect()
    }

    /// Reads one approval after runtime-side principal and scope checks.
    ///
    /// # Errors
    /// Returns a closed transport, capability, or response-validation error.
    pub async fn get_approval(&self, approval_id: CanonicalId) -> Result<ApprovalSummaryDto, RuntimeApiError> {
        require_capability(self, APPROVALS_CAPABILITY_V1)?;
        let response = self
            .authenticated_request(self.client.get(self.url(&format!("/v1/approvals/{approval_id}"))))?
            .send().await.map_err(map_transport)?;
        let approval: ApprovalSummaryDto = read_success_json::<ApprovalWire>(response, &[200]).await?.try_into()?;
        (approval.approval_id == approval_id).then_some(approval).ok_or_else(invalid_response)
    }

    /// Submits one idempotent, version-bound approval decision.
    ///
    /// # Errors
    /// Returns a closed transport, capability, or response-validation error.
    pub async fn decide_approval(
        &self,
        request: ApprovalDecisionRequest,
    ) -> Result<ApprovalDecisionAcknowledgementDto, RuntimeApiError> {
        require_capability(self, APPROVALS_CAPABILITY_V1)?;
        let expected_id = request.approval_id;
        let body = serde_json::to_vec(&ApprovalDecisionWire {
            expected_version: request.expected_version,
            decision: match request.decision { ApprovalDecisionDto::Approve => "approve", ApprovalDecisionDto::Deny => "deny" },
            action_digest: hex::encode(request.action_digest),
            policy_revision: request.policy_revision,
            renderer_generation: request.renderer_generation,
        }).map_err(|_| invalid_request())?;
        let response = self
            .command_request(self.client.post(self.url(&format!("/v1/approvals/{expected_id}/decision"))), &request.identity)?
            .header(CONTENT_TYPE, "application/json").body(body)
            .send().await.map_err(map_transport)?;
        let ack: ApprovalDecisionAcknowledgementDto = read_success_json::<ApprovalAcknowledgementWire>(response, &[202]).await?.try_into()?;
        (ack.approval_id == expected_id).then_some(ack).ok_or_else(invalid_response)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalListWire { items: Vec<ApprovalWire> }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalWire {
    approval_id: CanonicalId,
    task_run_id: CanonicalId,
    attempt_id: Option<CanonicalId>,
    invocation_id: CanonicalId,
    action: String,
    resource: String,
    action_digest: String,
    policy_revision: u64,
    request_version: u64,
    expires_at: i64,
    risk_summary: String,
    state: ApprovalStateWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalDecisionWire {
    expected_version: u64,
    decision: &'static str,
    action_digest: String,
    policy_revision: u64,
    renderer_generation: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalAcknowledgementWire {
    approval_id: CanonicalId,
    task_run_id: CanonicalId,
    new_version: u64,
    state: ApprovalStateWire,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ApprovalStateWire { Pending, Approved, Denied, Expired, Cancelled }

impl TryFrom<ApprovalWire> for ApprovalSummaryDto {
    type Error = RuntimeApiError;
    fn try_from(value: ApprovalWire) -> Result<Self, Self::Error> {
        let action_digest = parse_digest(&value.action_digest)?;
        validate_display(&value.action)?;
        validate_display(&value.resource)?;
        validate_display(&value.risk_summary)?;
        if value.policy_revision == 0 || value.request_version == 0 || value.expires_at <= 0 {
            return Err(invalid_response());
        }
        Ok(Self { approval_id: value.approval_id, task_run_id: value.task_run_id, attempt_id: value.attempt_id, invocation_id: value.invocation_id, action: value.action, resource: value.resource, action_digest, policy_revision: value.policy_revision, request_version: value.request_version, expires_at: value.expires_at, risk_summary: value.risk_summary, state: value.state.into() })
    }
}

impl TryFrom<ApprovalAcknowledgementWire> for ApprovalDecisionAcknowledgementDto {
    type Error = RuntimeApiError;
    fn try_from(value: ApprovalAcknowledgementWire) -> Result<Self, Self::Error> {
        if value.new_version == 0 || matches!(value.state, ApprovalStateWire::Pending) { return Err(invalid_response()); }
        Ok(Self { approval_id: value.approval_id, task_run_id: value.task_run_id, new_version: value.new_version, state: value.state.into() })
    }
}

impl From<ApprovalStateWire> for ApprovalStateDto {
    fn from(value: ApprovalStateWire) -> Self { match value { ApprovalStateWire::Pending => Self::Pending, ApprovalStateWire::Approved => Self::Approved, ApprovalStateWire::Denied => Self::Denied, ApprovalStateWire::Expired => Self::Expired, ApprovalStateWire::Cancelled => Self::Cancelled } }
}

fn parse_digest(value: &str) -> Result<[u8; 32], RuntimeApiError> {
    if value.len() != 64 || value != value.to_ascii_lowercase() { return Err(invalid_response()); }
    let bytes = hex::decode(value).map_err(|_| invalid_response())?;
    bytes.try_into().map_err(|_| invalid_response())
}

fn validate_display(value: &str) -> Result<(), RuntimeApiError> {
    if value.is_empty() || value.len() > MAX_APPROVAL_DISPLAY_BYTES || value.chars().any(char::is_control) { return Err(invalid_response()); }
    Ok(())
}
