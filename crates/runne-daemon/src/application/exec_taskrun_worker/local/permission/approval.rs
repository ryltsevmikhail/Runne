use super::capture::PreparedCurrentCommand;
use super::*;
use runne_api::{
    ApprovalCreateCommand, ApprovalQueryContext, ApprovalQueryHostPort, ApprovalRequestHostPort,
    ApprovalState,
};
use runne_application::permission_modes::{
    ManagedDisposition, ManagedPolicyEvaluation, NativeScopeAdmissionReceipt, PermissionAction,
    PermissionPolicyCompiler, PolicyDecision, PolicyEvaluationInput, ResourceFacts, Sensitivity,
    SizeBound, TargetState, WorkspaceRelation, admit_effective_mode, admit_invocation_scope,
};
use runne_application::project_trust::ManagedEffectDecision;
use runne_domain::id::ApprovalId;
use runne_store::ProjectWorkspaceStore;
use std::time::Duration;

pub(super) async fn admit(
    worker: &DaemonAutomaticTaskRuns,
    prepared: &PreparedCurrentCommand,
) -> Result<NativeScopeAdmissionReceipt, AutomaticTaskRunError> {
    let binding = &prepared.binding;
    let native = worker
        .store
        .local_permission_preparation()
        .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let port = native.invocation_scope_admission_port();
    let effective = admit_effective_mode(
        binding.selection().selected_mode,
        binding.selection().preset_version,
        binding.scope(),
        port,
    )
    .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
    let receipt = admit_invocation_scope(binding.scope(), port)
        .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
    let managed = match binding
        .scope()
        .managed_policy
        .scope_minimum_disposition(binding.scope())
        .ok_or(AutomaticTaskRunError::RejectedBeforeEffect)?
    {
        ManagedEffectDecision::Allow => ManagedDisposition::Allow,
        ManagedEffectDecision::Ask => ManagedDisposition::Ask,
        ManagedEffectDecision::Deny => ManagedDisposition::Deny,
    };
    let candidate = binding.approval().clone();
    let decision = PermissionPolicyCompiler::compile(&PolicyEvaluationInput {
        selection: binding.selection().clone(),
        effective_scope: binding.scope().clone(),
        effective,
        invocation: runne_application::permission_modes::InvocationPolicyRequest {
            action: PermissionAction::ProcessStart,
            resource: ResourceFacts {
                workspace: WorkspaceRelation::Inside,
                sensitivity: Sensitivity::Unknown,
                size: SizeBound::Unknown,
                resolution: runne_application::permission_modes::ResolutionState::HeldSafe,
                resolved_path: None,
                target: TargetState::Existing,
                object: runne_application::permission_modes::ObjectKind::Other,
                executable: true,
            },
            composite_scope: binding.scope().clone(),
            candidate_binding: candidate.clone(),
            approved_binding: None,
            native_admission: Some(receipt),
        },
        managed: ManagedPolicyEvaluation {
            scope_digest: binding
                .scope()
                .digest()
                .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?,
            policy_digest: binding.scope().managed_policy.policy_digest(),
            disposition: managed,
        },
        now_unix_ms: super::now_millis(),
    });
    match decision {
        PolicyDecision::Allow {
            native_admission, ..
        } => {
            worker
                .store
                .admit_local_command_permission(binding, None)
                .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
            Ok(native_admission)
        }
        PolicyDecision::RequireApproval { .. } => {
            let id = ApprovalId::from_bytes(*binding.invocation_id().as_bytes());
            await_exact_approval(worker, prepared, id).await?;
            worker
                .store
                .admit_local_command_permission(binding, Some(id))
                .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
            Ok(receipt)
        }
        PolicyDecision::Deny(_) => Err(AutomaticTaskRunError::RejectedBeforeEffect),
    }
}

async fn await_exact_approval(
    worker: &DaemonAutomaticTaskRuns,
    prepared: &PreparedCurrentCommand,
    id: ApprovalId,
) -> Result<(), AutomaticTaskRunError> {
    let binding = &prepared.binding;
    let approvals = ProjectWorkspaceStore::from_store(worker.store.clone());
    let query = ApprovalQueryContext {
        principal: prepared.principal.clone(),
    };
    let review = super::approval_review_summary_for_scope(&prepared.command, binding.scope())?;
    let resource = super::approval_resource(prepared.identity.taskrun_id, prepared.workspace);
    let mut summary = match approvals.get_approval(query.clone(), id).await {
        Ok(value) => value,
        Err(runne_api::ApprovalHostError::NotFound) => {
            let request = ApprovalCreateCommand::new(
                id,
                prepared.identity.taskrun_id,
                Some(prepared.identity.attempt_id),
                binding.invocation_id(),
                prepared.principal.clone(),
                super::APPROVAL_ACTION,
                resource.clone(),
                *binding.approval().digest().as_bytes(),
                runne_application::project_trust::LOCAL_COMMAND_POLICY_VERSION,
                1,
                binding.approval().expires_at_unix_ms,
                review,
            )
            .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
            approvals
                .create_pending_approval(request)
                .await
                .map_err(|_| AutomaticTaskRunError::Unavailable)?
        }
        Err(_) => return Err(AutomaticTaskRunError::Unavailable),
    };
    loop {
        validate_summary(&summary, prepared, id, &resource)?;
        match summary.state() {
            ApprovalState::Approved => return Ok(()),
            ApprovalState::Denied | ApprovalState::Expired | ApprovalState::Cancelled => {
                return Err(AutomaticTaskRunError::RejectedBeforeEffect);
            }
            ApprovalState::Pending => {}
        }
        if super::now_millis() >= binding.approval().expires_at_unix_ms {
            return Err(AutomaticTaskRunError::RejectedBeforeEffect);
        }
        let stream = worker
            .store
            .load_task_run(prepared.identity.taskrun_id)
            .map_err(|_| AutomaticTaskRunError::Unavailable)?;
        let task = TaskRun::replay(&stream.events).map_err(|_| AutomaticTaskRunError::Uncertain)?;
        if task.state() != TaskRunState::Running
            || worker
                .current_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                != prepared.identity.node_epoch
        {
            return Err(AutomaticTaskRunError::RejectedBeforeEffect);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        summary = approvals
            .get_approval(query.clone(), id)
            .await
            .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    }
}

fn validate_summary(
    summary: &runne_api::ApprovalSummary,
    prepared: &PreparedCurrentCommand,
    id: ApprovalId,
    resource: &str,
) -> Result<(), AutomaticTaskRunError> {
    let binding = &prepared.binding;
    if summary.approval_id() != id
        || summary.task_run_id() != prepared.identity.taskrun_id
        || summary.attempt_id() != Some(prepared.identity.attempt_id)
        || summary.invocation_id() != binding.invocation_id()
        || summary.action() != super::APPROVAL_ACTION
        || summary.resource() != resource
        || summary.action_digest() != binding.approval().digest().as_bytes()
        || summary.policy_revision()
            != runne_application::project_trust::LOCAL_COMMAND_POLICY_VERSION
        || !request_version_matches(summary.state(), summary.request_version())
        || summary.expires_at() != binding.approval().expires_at_unix_ms
        || summary.expires_at() <= super::now_millis()
    {
        return Err(AutomaticTaskRunError::RejectedBeforeEffect);
    }
    Ok(())
}

fn request_version_matches(state: ApprovalState, version: u64) -> bool {
    match state {
        ApprovalState::Pending => version == 1,
        ApprovalState::Approved => version == 2,
        ApprovalState::Denied | ApprovalState::Expired | ApprovalState::Cancelled => false,
    }
}

#[cfg(test)]
mod tests {
    use super::request_version_matches;
    use runne_api::ApprovalState;

    #[test]
    fn approval_summary_version_follows_pending_and_decision_transition() {
        assert!(request_version_matches(ApprovalState::Pending, 1));
        assert!(!request_version_matches(ApprovalState::Pending, 2));
        assert!(request_version_matches(ApprovalState::Approved, 2));
        assert!(!request_version_matches(ApprovalState::Approved, 1));
        for state in [
            ApprovalState::Denied,
            ApprovalState::Expired,
            ApprovalState::Cancelled,
        ] {
            assert!(!request_version_matches(state, 1));
            assert!(!request_version_matches(state, 2));
        }
    }
}
