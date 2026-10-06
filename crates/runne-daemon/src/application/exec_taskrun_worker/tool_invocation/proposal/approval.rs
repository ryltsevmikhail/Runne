use super::*;
use runne_application::ports::ApplicationCommandContext;
use runne_application::ports::TaskRunAssignmentIdentity;
use runne_store::store::taskrun_tool_invocation::ToolInvocationBindingV1;

impl crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns {
    pub(super) async fn await_approval_and_execute(
        &self,
        context: &ApplicationCommandContext,
        assignment: &TaskRunAssignmentIdentity,
        workspace_id: runne_domain::id::WorkspaceId,
        binding: ToolInvocationBindingV1,
        principal: ApiPrincipalId,
        prepared: super::super::permission::PreparedPermissionInvocation,
    ) -> Result<(), ()> {
        let key = binding.key;
        let approval_id = binding.approval_id;
        let invocation_id =
            stable(&[b"RUNNE_D2_TOOL_INVOCATION_ID_V1\0".as_slice(), &approval_id].concat());
        let approval_digest = binding.approval_digest;
        let expires_at = binding.approval_expires_at;
        let resource = binding.approval_resource.clone();
        let risk_summary = format!(
            "Approve {} for workspace file {}",
            binding.tool_name, binding.target_name
        );
        let approval_store = ProjectWorkspaceStore::from_store(self.store.clone());
        let principal_text = principal.as_str().to_owned();
        let mut disposition = ApprovalDisposition::Pending;
        let mut next_renewal = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while disposition == ApprovalDisposition::Pending {
            if now_millis() >= expires_at {
                return Ok(());
            }
            if self
                .current_epoch
                .load(std::sync::atomic::Ordering::Acquire)
                != assignment.node_epoch
            {
                return Err(());
            }
            let active = self
                .store
                .load_task_run(assignment.taskrun_id)
                .map_err(|_| ())?;
            let task = TaskRun::replay(&active.events).map_err(|_| ())?;
            if active.current_version != binding.expected_taskrun_version
                || task.state() != runne_domain::task_run::TaskRunState::Running
                || !task
                    .snapshot_v1()
                    .active_cycle()
                    .is_some_and(|active_cycle| {
                        active_cycle.cycle_id == key.cycle_id
                            && active_cycle.attempt_id == assignment.attempt_id
                    })
            {
                return Err(());
            }
            disposition = ensure_human_approval(
                approval_store.clone(),
                assignment.taskrun_id,
                assignment.attempt_id,
                approval_id,
                invocation_id,
                principal.clone(),
                resource.clone(),
                *approval_digest.as_bytes(),
                expires_at,
                risk_summary.clone(),
            )
            .await?;
            crate::application::exec_taskrun_worker::provider::d2_stage(match disposition {
                ApprovalDisposition::Pending => "approval_pending",
                ApprovalDisposition::Approved => "approval_approved",
                ApprovalDisposition::Denied => "approval_denied",
            });
            if disposition == ApprovalDisposition::Pending {
                if std::time::Instant::now() >= next_renewal {
                    self.store
                        .renew_taskrun_assignment_lease(
                            runne_application::ports::TaskRunLeaseRenewal {
                                identity: assignment.clone(),
                                renewal_id: runne_domain::id::CommandId::from_bytes(
                                    *uuid::Uuid::now_v7().as_bytes(),
                                ),
                                lease_duration_ms: 300_000,
                            },
                        )
                        .map_err(|_| ())?;
                    next_renewal = std::time::Instant::now() + std::time::Duration::from_secs(30);
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        }
        if matches!(
            disposition,
            ApprovalDisposition::Approved | ApprovalDisposition::Denied
        ) {
            self.store
                .bind_taskrun_tool_approval(
                    runne_store::store::taskrun_tool_invocation::ToolApprovalBindingV1 {
                        key,
                        approval_id,
                        decision_principal_id: principal_text,
                        expected_policy_revision: POLICY_REVISION,
                        expected_action_digest: approval_digest,
                    },
                    assignment,
                    now_millis(),
                )
                .map_err(|_| ())?;
        }
        if disposition == ApprovalDisposition::Approved {
            let worker = self.clone();
            let context = context.clone();
            let assignment = assignment.clone();
            tokio::task::spawn_blocking(move || {
                worker.execute_approved_tool_effect(
                    &context,
                    &assignment,
                    workspace_id,
                    &binding,
                    &prepared,
                )
            })
            .await
            .map_err(|_| ())??;
            crate::application::exec_taskrun_worker::provider::d2_stage("native_effect_recorded");
        }
        Ok(())
    }
}
