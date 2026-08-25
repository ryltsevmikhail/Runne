impl MutationRequest {
    /// Creates a versioned, policy-bound approval decision request.
    ///
    /// # Errors
    /// Returns a closed error when a decision binding is invalid.
    pub fn respond_to_approval(
        approval_id: CanonicalId,
        expected_version: u64,
        decision: runne_runtime_client::ApprovalDecisionDto,
        action_digest: [u8; 32],
        policy_revision: u64,
        renderer_generation: u64,
    ) -> Result<Self, AppCoreError> {
        if expected_version == 0
            || policy_revision == 0
            || renderer_generation == 0
            || action_digest == [0; 32]
        {
            return Err(AppCoreError::InvalidMutation);
        }
        Self::new(
            runne_local_store::MutationOperation::ApprovalRespond,
            runne_local_store::MutationTargetKind::Approval,
            approval_id,
            expected_version,
            CanonicalMutationCommand::ApprovalRespond {
                approval_id,
                decision,
                action_digest,
                policy_revision,
                renderer_generation,
            },
        )
    }
}
