impl ApprovalQueryHostPort for ProjectWorkspaceStore {
    fn list_pending_approvals(
        &self,
        context: ApprovalQueryContext,
    ) -> impl std::future::Future<Output = Result<Vec<ApprovalSummary>, ApprovalHostError>> + Send
    {
        let store = self.clone();
        async move {
            store
                .store
                .with_project_workspace_transaction(|transaction| {
                    expire_pending(transaction, Some(context.principal.as_str()), None)?;
                    let mut statement = transaction
                        .prepare("SELECT approval_id, task_run_id, attempt_id, invocation_id, principal_id, action, resource, action_digest, policy_revision, request_version, renderer_generation, expires_at, risk_summary, state, decision_command_id, decision_idempotency_key, decision_principal_id, decision, updated_at FROM approvals WHERE principal_id = ?1 AND state = 1 ORDER BY expires_at, approval_id")
                        .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)?;
                    let rows = statement
                        .query_map([context.principal.as_str()], read_row)
                        .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)?;
                    rows.map(|row| row.map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation).and_then(summary))
                        .collect::<Result<Vec<_>, _>>()
                })
                .map_err(map_query_error)
        }
    }

    fn get_approval(
        &self,
        context: ApprovalQueryContext,
        approval_id: ApprovalId,
    ) -> impl std::future::Future<Output = Result<ApprovalSummary, ApprovalHostError>> + Send {
        let store = self.clone();
        async move {
            store
                .store
                .with_project_workspace_transaction(|transaction| {
                    let approval_key = approval_id.to_string();
                    expire_pending(
                        transaction,
                        Some(context.principal.as_str()),
                        Some(&approval_key),
                    )?;
                    transaction
                        .query_row("SELECT approval_id, task_run_id, attempt_id, invocation_id, principal_id, action, resource, action_digest, policy_revision, request_version, renderer_generation, expires_at, risk_summary, state, decision_command_id, decision_idempotency_key, decision_principal_id, decision, updated_at FROM approvals WHERE approval_id = ?1 AND principal_id = ?2", params![approval_key, context.principal.as_str()], read_row)
                        .optional()
                        .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)?
                        .ok_or(runne_application::ports::ProjectWorkspaceRepositoryError::NotFound)
                        .and_then(summary)
                })
                .map_err(map_query_error)
        }
    }
}
