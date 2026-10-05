impl AppCore {
    /// Reads authoritative `TaskRun` snapshots through the runtime client.
    ///
    /// # Errors
    /// Returns an error when the runtime snapshot is unavailable or exceeds
    /// the bounded inventory size.
    pub async fn list_managed_task_runs(&self) -> Result<ManagedTaskRunList, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.task_run_read_context()?;
        let snapshots = context
            .client
            .list_task_runs()
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        self.require_current_operation_context(&context)?;
        if snapshots.len() > MANAGED_TASK_RUN_LIMIT {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        Ok(ManagedTaskRunList {
            status: "available",
            task_runs: snapshots
                .into_iter()
                .map(|value| ManagedTaskRunItem {
                    task_run_id: value.task_run_id().to_string(),
                    workspace_id: value.workspace_id().map(|id| id.to_string()),
                    conversation_id: value.conversation_id().map(|id| id.to_string()),
                    state: task_run_state_name(value.state()),
                    terminal: task_run_terminal(value.state(), value.terminal_result()),
                    stream_version: value.stream_version(),
                    active_attempt_id: value.active_attempt_id().map(|id| id.to_string()),
                })
                .collect(),
        })
    }

    /// Builds a bounded attention projection from authoritative runtime state.
    ///
    /// # Errors
    /// Returns an error when `TaskRun` or approval snapshots are unavailable.
    pub async fn managed_attention_snapshot(
        &self,
    ) -> Result<ManagedAttentionSnapshot, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.task_run_read_context()?;
        let snapshots = context
            .client
            .list_task_runs()
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        self.require_current_operation_context(&context)?;
        if snapshots.len() > MANAGED_TASK_RUN_LIMIT {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let effects = self
            .read_managed_attention_effects(&context, &snapshots)
            .await;
        let mut items: Vec<_> = snapshots
            .iter()
            .filter_map(|run| {
                let terminal = task_run_terminal(run.state(), run.terminal_result());
                let kind = match terminal {
                    Some(TaskRunTerminalDisposition::Failure
                    | TaskRunTerminalDisposition::PolicyDenied
                    | TaskRunTerminalDisposition::BudgetExhausted) => "failed",
                    _ => match task_run_state_name(run.state()) {
                        "failed" | "policy_denied" | "budget_exhausted" => "failed",
                        "reconciling" | "unrecoverable" => "uncertain",
                        _ => return None,
                    },
                };
                Some(ManagedAttentionItem {
                    approval_id: None,
                    task_run_id: Some(run.task_run_id().to_string()),
                    kind,
                    workspace_id: run.workspace_id().map(|id| id.to_string()),
                    conversation_id: run.conversation_id().map(|id| id.to_string()),
                })
            })
            .collect();
        for task_run_id in effects.uncertain_task_run_ids {
            let id = task_run_id.to_string();
            if !items.iter().any(|item| {
                item.kind == "uncertain" && item.task_run_id.as_deref() == Some(&id)
            }) {
                let run = snapshots
                    .iter()
                    .find(|run| run.task_run_id() == task_run_id);
                items.push(ManagedAttentionItem {
                    approval_id: None,
                    task_run_id: Some(id),
                    kind: "uncertain",
                    workspace_id: run
                        .and_then(runne_runtime_client::TaskRunSnapshot::workspace_id)
                        .map(|value| value.to_string()),
                    conversation_id: run
                        .and_then(runne_runtime_client::TaskRunSnapshot::conversation_id)
                        .map(|value| value.to_string()),
                });
            }
        }
        let approvals = context
            .client
            .list_pending_approvals()
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        self.require_current_operation_context(&context)?;
        items.extend(approvals.iter().map(|approval| ManagedAttentionItem {
            approval_id: Some(approval.approval_id().to_string()),
            task_run_id: Some(approval.task_run_id().to_string()),
            kind: "approval",
            workspace_id: None,
            conversation_id: None,
        }));
        items.push(ManagedAttentionItem {
            approval_id: None,
            task_run_id: None,
            kind: "effective_authority_unavailable",
            workspace_id: None,
            conversation_id: None,
        });
        let effects_gap = !effects.complete;
        let complete = !effects_gap && items.len() <= MANAGED_ATTENTION_LIMIT;
        if effects_gap {
            items.truncate(MANAGED_ATTENTION_LIMIT.saturating_sub(1));
            items.push(ManagedAttentionItem {
                approval_id: None,
                task_run_id: None,
                kind: "effects_unavailable",
                workspace_id: None,
                conversation_id: None,
            });
        } else {
            items.truncate(MANAGED_ATTENTION_LIMIT);
        }
        Ok(ManagedAttentionSnapshot {
            status: "available",
            complete,
            items,
        })
    }
}
