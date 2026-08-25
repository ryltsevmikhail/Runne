impl ApprovalCommandHostPort for ProjectWorkspaceStore {
    fn decide_approval(
        &self,
        context: ApprovalCommandContext,
        command: ApprovalDecisionCommand,
    ) -> impl std::future::Future<Output = Result<ApprovalDecisionAck, ApprovalHostError>> + Send
    {
        let store = self.clone();
        async move {
            match store
                .store
                .with_project_workspace_transaction(|transaction| {
                    decide(transaction, &context, &command)
                })
                .map_err(map_command_error)?
            {
                ack if ack.state() == ApprovalState::Expired => Err(ApprovalHostError::Expired),
                ack => Ok(ack),
            }
        }
    }
}

fn decide(
    transaction: &Transaction<'_>,
    context: &ApprovalCommandContext,
    command: &ApprovalDecisionCommand,
) -> Result<ApprovalDecisionAck, runne_application::ports::ProjectWorkspaceRepositoryError> {
    let row = transaction
        .query_row("SELECT approval_id, task_run_id, attempt_id, invocation_id, principal_id, action, resource, action_digest, policy_revision, request_version, renderer_generation, expires_at, risk_summary, state, decision_command_id, decision_idempotency_key, decision_principal_id, decision, updated_at FROM approvals WHERE approval_id = ?1", [command.approval_id().to_string()], read_row)
        .optional()
        .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)?
        .ok_or(runne_application::ports::ProjectWorkspaceRepositoryError::NotFound)?;
    let approval_id = parse_id::<ApprovalId>(&row.0)?;
    let task_run_id = parse_id::<TaskRunId>(&row.1)?;
    let current_state = state(row.13)?;
    if row.4 != context.principal.as_str() {
        return Err(runne_application::ports::ProjectWorkspaceRepositoryError::Forbidden);
    }
    if let Some(stored_command_id) = row.14.as_deref() {
        let stored_state = state(row.13)?;
        let expected_decision = match command.decision() {
            ApprovalDecision::Approve => 1_i64,
            ApprovalDecision::Deny => 2_i64,
        };
        let same_command = stored_command_id == context.command_id.as_bytes()
            && row.15.as_deref() == Some(context.idempotency_key.as_str())
            && row.16.as_deref() == Some(context.principal.as_str())
            && row.17 == Some(expected_decision)
            && row.9 == command.expected_version().saturating_add(1)
            && matches!(
                stored_state,
                ApprovalState::Approved | ApprovalState::Denied
            );
        if same_command {
            return ApprovalDecisionAck::new(approval_id, task_run_id, row.9, stored_state)
                .map_err(|_| {
                    runne_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation
                });
        }
        return Err(runne_application::ports::ProjectWorkspaceRepositoryError::Conflict);
    }
    if current_state != ApprovalState::Pending {
        return Err(runne_application::ports::ProjectWorkspaceRepositoryError::Conflict);
    }
    if row.8 != command.policy_revision()
        || row.9 != command.expected_version()
        || row.10 != command.renderer_generation()
        || row.7.as_slice() != command.action_digest()
    {
        return Err(runne_application::ports::ProjectWorkspaceRepositoryError::Conflict);
    }
    let now = unix_millis();
    if row.11 <= now {
        transaction.execute("UPDATE approvals SET state = 4, request_version = request_version + 1, updated_at = ?1 WHERE approval_id = ?2 AND state = 1", params![now, command.approval_id().to_string()]).map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)?;
        return ApprovalDecisionAck::new(
            approval_id,
            task_run_id,
            command.expected_version().checked_add(1).ok_or(
                runne_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation,
            )?,
            ApprovalState::Expired,
        )
        .map_err(|_| {
            runne_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation
        });
    }
    let next = command
        .expected_version()
        .checked_add(1)
        .ok_or(runne_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation)?;
    let decision = match command.decision() {
        ApprovalDecision::Approve => 1_i64,
        ApprovalDecision::Deny => 2_i64,
    };
    let changed = transaction.execute("UPDATE approvals SET state = ?1, request_version = ?2, decision_command_id = ?3, decision_idempotency_key = ?4, decision_principal_id = ?5, decision = ?6, decided_at = ?7, updated_at = ?7 WHERE approval_id = ?8 AND state = 1 AND request_version = ?9", params![if decision == 1 { 2 } else { 3 }, next, context.command_id.as_bytes(), context.idempotency_key.as_str(), context.principal.as_str(), decision, now, command.approval_id().to_string(), command.expected_version()]).map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)?;
    if changed != 1 {
        return Err(runne_application::ports::ProjectWorkspaceRepositoryError::Conflict);
    }
    ApprovalDecisionAck::new(
        approval_id,
        task_run_id,
        next,
        if decision == 1 {
            ApprovalState::Approved
        } else {
            ApprovalState::Denied
        },
    )
    .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation)
}
