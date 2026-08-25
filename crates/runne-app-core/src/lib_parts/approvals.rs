impl AppCore {
    /// Reads the runtime-owned approval queue for the authenticated principal.
    ///
    /// # Errors
    /// Returns a closed error when the runtime is unavailable or the response is invalid.
    pub async fn list_pending_approvals(
        &self,
    ) -> Result<Vec<CanonicalApprovalSummary>, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        self.live_runtime_client()?
            .list_pending_approvals()
            .await
            .map(|items| items.iter().map(CanonicalApprovalSummary::from).collect())
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    /// Reads one current approval authority projection by opaque identity.
    ///
    /// # Errors
    /// Returns a closed error when the ID is invalid, unauthorized, or the runtime is unavailable.
    pub async fn get_approval(
        &self,
        approval_id: &str,
    ) -> Result<CanonicalApprovalSummary, AppCoreError> {
        let approval_id = CanonicalId::parse(approval_id)
            .map_err(|_| AppCoreError::InvalidMutation)?;
        let _operation = self.runtime_operation.lock().await;
        self.live_runtime_client()?
            .get_approval(approval_id)
            .await
            .map(|value| CanonicalApprovalSummary::from(&value))
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    /// Commits a policy-bound approval decision through the durable mutation ledger.
    ///
    /// # Errors
    /// Returns a closed error when bindings are stale, the runtime is unavailable, or the decision is rejected.
    pub async fn respond_to_approval(
        &self,
        approval_id: &str,
        expected_version: u64,
        decision: runne_runtime_client::ApprovalDecisionDto,
        action_digest: &str,
        policy_revision: u64,
        renderer_generation: u64,
    ) -> Result<runne_runtime_client::ApprovalDecisionAcknowledgementDto, AppCoreError> {
        let approval_id = CanonicalId::parse(approval_id).map_err(|_| AppCoreError::InvalidMutation)?;
        let digest = hex::decode(action_digest)
            .ok()
            .and_then(|value| value.try_into().ok())
            .ok_or(AppCoreError::InvalidMutation)?;
        let lease = self.prepare_mutation(MutationRequest::respond_to_approval(
            approval_id, expected_version, decision, digest, policy_revision, renderer_generation,
        )?).await?;
        match self.dispatch_prepared_mutation(lease).await? {
            MutationDispatchResult::ApprovalDecision(value) => Ok(value),
            _ => Err(AppCoreError::InvalidMutation),
        }
    }
}

/// Renderer-safe approval projection. It contains no native authority or
/// protected action payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalApprovalSummary {
    pub approval_id: String,
    pub task_run_id: String,
    pub attempt_id: Option<String>,
    pub invocation_id: String,
    pub action: String,
    pub resource: String,
    pub action_digest: String,
    pub policy_revision: u64,
    pub request_version: u64,
    pub expires_at: i64,
    pub risk_summary: String,
    pub state: CanonicalApprovalState,
}

impl From<&runne_runtime_client::ApprovalSummaryDto> for CanonicalApprovalSummary {
    fn from(value: &runne_runtime_client::ApprovalSummaryDto) -> Self {
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
            expires_at: value.expires_at(),
            risk_summary: value.risk_summary().to_owned(),
            state: CanonicalApprovalState::from(value.state()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalApprovalState {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

impl From<runne_runtime_client::ApprovalStateDto> for CanonicalApprovalState {
    fn from(value: runne_runtime_client::ApprovalStateDto) -> Self {
        match value {
            runne_runtime_client::ApprovalStateDto::Pending => Self::Pending,
            runne_runtime_client::ApprovalStateDto::Approved => Self::Approved,
            runne_runtime_client::ApprovalStateDto::Denied => Self::Denied,
            runne_runtime_client::ApprovalStateDto::Expired => Self::Expired,
            runne_runtime_client::ApprovalStateDto::Cancelled => Self::Cancelled,
        }
    }
}
