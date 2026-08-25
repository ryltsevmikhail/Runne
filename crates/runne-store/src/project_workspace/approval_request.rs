impl ApprovalRequestHostPort for ProjectWorkspaceStore {
    fn create_pending_approval(
        &self,
        command: ApprovalCreateCommand,
    ) -> impl std::future::Future<Output = Result<ApprovalSummary, ApprovalHostError>> + Send {
        let store = self.clone();
        async move {
            store
                .store
                .with_project_workspace_transaction(|transaction| {
                    create_pending(transaction, &command)
                })
                .map_err(map_command_error)
        }
    }
}

fn create_pending(
    transaction: &Transaction<'_>,
    command: &ApprovalCreateCommand,
) -> Result<ApprovalSummary, runne_application::ports::ProjectWorkspaceRepositoryError> {
    let approval_id = command.approval_id().to_string();
    let existing = transaction
        .query_row(
            "SELECT approval_id, task_run_id, attempt_id, invocation_id, principal_id, action, resource, action_digest, policy_revision, request_version, renderer_generation, expires_at, risk_summary, state, decision_command_id, decision_idempotency_key, decision_principal_id, decision, updated_at FROM approvals WHERE approval_id = ?1",
            [&approval_id],
            read_row,
        )
        .optional()
        .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)?;
    if let Some(row) = existing {
        if !matches_request(&row, command) {
            return Err(runne_application::ports::ProjectWorkspaceRepositoryError::Conflict);
        }
        return summary(row);
    }
    let now = unix_millis();
    transaction
        .execute(
            "INSERT INTO approvals (approval_id, task_run_id, attempt_id, invocation_id,
             principal_id, action, resource, action_digest, policy_revision, request_version,
             renderer_generation, expires_at, risk_summary, state, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11, ?12, 1, ?13)",
            params![
                approval_id,
                command.task_run_id().to_string(),
                command.attempt_id().map(|id| id.to_string()),
                command.invocation_id().to_string(),
                command.principal().as_str(),
                command.action(),
                command.resource(),
                command.action_digest().as_slice(),
                command.policy_revision(),
                command.renderer_generation(),
                command.expires_at(),
                command.risk_summary(),
                now,
            ],
        )
        .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::Conflict)?;
    transaction
        .query_row(
            "SELECT approval_id, task_run_id, attempt_id, invocation_id, principal_id, action, resource, action_digest, policy_revision, request_version, renderer_generation, expires_at, risk_summary, state, decision_command_id, decision_idempotency_key, decision_principal_id, decision, updated_at FROM approvals WHERE approval_id = ?1",
            [command.approval_id().to_string()],
            read_row,
        )
        .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)
        .and_then(summary)
}

fn matches_request(row: &Row, command: &ApprovalCreateCommand) -> bool {
    row.1 == command.task_run_id().to_string()
        && row.2.as_deref() == command.attempt_id().map(|id| id.to_string()).as_deref()
        && row.3 == command.invocation_id().to_string()
        && row.4 == command.principal().as_str()
        && row.5 == command.action()
        && row.6 == command.resource()
        && row.7.as_slice() == command.action_digest()
        && row.8 == command.policy_revision()
        && row.9 == 1
        && row.10 == command.renderer_generation()
        && row.11 == command.expires_at()
        && row.12 == command.risk_summary()
}
