/// Immutable approval tuple supplied by the authenticated runtime.
/// It intentionally has no serde implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalConfirmationParts {
    pub approval_id: CanonicalId,
    pub task_run_id: CanonicalId,
    pub attempt_id: Option<CanonicalId>,
    pub invocation_id: CanonicalId,
    pub action: String,
    pub resource: String,
    pub action_digest: [u8; 32],
    pub policy_revision: u64,
    pub approval_generation: u64,
    pub expires_at: i64,
}

/// The specific decision and version the user confirmed.
/// It intentionally has no serde implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalDecisionBinding {
    pub expected_version: u64,
    pub decision: ApprovalDecisionDto,
}

/// Host-only approval authority binding. It intentionally has no serde implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalConfirmationBinding {
    admission: MutationAdmissionBinding,
    parts: ApprovalConfirmationParts,
    request: ApprovalDecisionBinding,
    renderer_generation: u64,
}

impl ApprovalConfirmationBinding {
    /// Creates one complete, non-renderer approval confirmation binding.
    ///
    /// # Errors
    /// Returns an invalid-mutation error when any authority component is empty,
    /// zeroed, or expired.
    pub fn new(
        admission: MutationAdmissionBinding,
        parts: ApprovalConfirmationParts,
        request: ApprovalDecisionBinding,
    ) -> Result<Self, AppCoreError> {
        if parts.action.is_empty()
            || parts.resource.is_empty()
            || parts.action_digest == [0; 32]
            || parts.policy_revision == 0
            || parts.approval_generation == 0
            || parts.expires_at <= 0
        {
            return Err(AppCoreError::InvalidMutation);
        }
        Ok(Self {
            admission,
            parts,
            request,
            renderer_generation: 1,
        })
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.parts.expires_at
    }

    #[must_use]
    pub const fn task_run_id(&self) -> CanonicalId {
        self.parts.task_run_id
    }

    #[must_use]
    pub fn action(&self) -> &str {
        &self.parts.action
    }

    #[must_use]
    pub fn resource(&self) -> &str {
        &self.parts.resource
    }

    #[must_use]
    pub const fn decision(&self) -> ApprovalDecisionDto {
        self.request.decision
    }

    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

impl AppCore {
    /// Fetches and binds the current runtime approval before native confirmation.
    ///
    /// # Errors
    /// Returns a closed error when an ID or digest is invalid, the approval is
    /// stale, or the authenticated runtime cannot provide its current authority.
    pub async fn prepare_approval_confirmation(
        &self,
        approval_id: &str,
        expected_version: u64,
        decision: ApprovalDecisionDto,
        action_digest: &str,
        policy_revision: u64,
        renderer_generation: u64,
    ) -> Result<ApprovalConfirmationBinding, AppCoreError> {
        let approval_id =
            CanonicalId::parse(approval_id).map_err(|_| AppCoreError::InvalidMutation)?;
        let digest = approval_digest(action_digest)?;
        let _operation = self.runtime_operation.lock().await;
        let client = self.live_runtime_client()?;
        let admission =
            self.mutation_binding_for(&replay::StableRuntimeIdentity::from_client(&client));
        let value = client
            .get_approval(approval_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let mut binding = approval_binding(
            admission,
            &value,
            ApprovalDecisionBinding {
                expected_version,
                decision,
            },
            digest,
            policy_revision,
        )?;
        if renderer_generation == 0 {
            return Err(AppCoreError::InvalidMutation);
        }
        binding.renderer_generation = renderer_generation;
        Ok(binding)
    }

    /// Verifies that an earlier native confirmation still matches runtime authority.
    ///
    /// # Errors
    /// Returns a closed error when the runtime has changed, revoked, or can no
    /// longer authenticate the approval tuple.
    pub async fn commit_approval_confirmation(
        &self,
        expected: &ApprovalConfirmationBinding,
    ) -> Result<runne_runtime_client::ApprovalDecisionAcknowledgementDto, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let client = self.live_runtime_client()?;
        let admission =
            self.mutation_binding_for(&replay::StableRuntimeIdentity::from_client(&client));
        let value = client
            .get_approval(expected.parts.approval_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let mut actual = approval_binding(
            admission,
            &value,
            expected.request,
            expected.parts.action_digest,
            expected.parts.policy_revision,
        )?;
        actual.renderer_generation = expected.renderer_generation;
        if !expected.matches(&actual) {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let lease = self.prepare_mutation_under_operation(MutationRequest::respond_to_approval(
            expected.parts.approval_id,
            expected.request.expected_version,
            expected.request.decision,
            expected.parts.action_digest,
            expected.parts.policy_revision,
            expected.parts.approval_generation,
        )?)?;
        match self
            .dispatch_prepared_mutation_under_operation(&mut { lease }, None, false, false, false)
            .await?
        {
            MutationDispatchResult::ApprovalDecision(value) => Ok(value),
            _ => Err(AppCoreError::InvalidMutation),
        }
    }
}

fn approval_binding(
    admission: MutationAdmissionBinding,
    value: &runne_runtime_client::ApprovalSummaryDto,
    request: ApprovalDecisionBinding,
    action_digest: [u8; 32],
    policy_revision: u64,
) -> Result<ApprovalConfirmationBinding, AppCoreError> {
    if !value.requires_decision()
        || value.request_version() != request.expected_version
        || value.action_digest() != &action_digest
        || value.policy_revision() != policy_revision
    {
        return Err(AppCoreError::RuntimeUnavailable);
    }
    ApprovalConfirmationBinding::new(
        admission,
        ApprovalConfirmationParts {
            approval_id: value.approval_id(),
            task_run_id: value.task_run_id(),
            attempt_id: value.attempt_id(),
            invocation_id: value.invocation_id(),
            action: value.action().to_owned(),
            resource: value.resource().to_owned(),
            action_digest,
            policy_revision,
            approval_generation: value.approval_generation(),
            expires_at: value.expires_at(),
        },
        request,
    )
}

fn approval_digest(value: &str) -> Result<[u8; 32], AppCoreError> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(AppCoreError::InvalidMutation)
}
