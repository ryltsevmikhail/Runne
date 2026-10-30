use super::*;
use runne_application::ports::EventStore;
use runne_application::ports::TaskRunAssignmentIdentity;
use runne_application::ports::TaskRunAssignmentPort;
use runne_domain::{id::IntegrityDigest, task_run::TaskRun};
use runne_store::store::taskrun_tool_invocation::{
    EncryptedToolPayloadV1, ToolInvocationBindingV1, ToolInvocationKey, ToolSourceRef,
};
#[path = "proposal/approval.rs"]
mod approval;
#[path = "proposal/preview.rs"]
mod preview;
#[path = "proposal/store_error.rs"]
mod store_error;

const ENVIRONMENT_ID: &str = "linux-agent-tools-v1";
const ENVIRONMENT_REVISION: &str = "1";

impl super::super::DaemonAutomaticTaskRuns {
    // Persisting a proposal requires the exact round, source, principal and workspace together.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::application) async fn persist_tool_proposal(
        &self,
        context: &runne_application::ports::ApplicationCommandContext,
        assignment: &TaskRunAssignmentIdentity,
        round_index: u32,
        proposal_index: u32,
        current_version: u64,
        call: runne_runtime::provider_tool::RuntimeToolCall,
        sources: Vec<ToolSourceRef>,
        workspace_id: runne_domain::id::WorkspaceId,
        principal: ApiPrincipalId,
    ) -> Result<(), ()> {
        super::super::provider::d2_stage("proposal_validating");
        let coding = self
            .provider
            .as_ref()
            .is_some_and(|p| p.coding_agent_tools_enabled());
        let environment_id = if coding {
            crate::safe_tool_helper::coding_arguments::ENVIRONMENT
        } else {
            ENVIRONMENT_ID
        };
        let (path, content) = parse_arguments(&call, coding).map_err(|_| {
            super::super::provider::d2_stage("proposal_error_arguments");
        })?;
        if sources.len() != 2
            || !sources.iter().any(|s| s.event_kind == 4 && !s.terminal)
            || !sources.iter().any(|s| s.event_kind == 5 && s.terminal)
        {
            super::super::provider::d2_stage("proposal_error_sources");
            return Err(());
        }
        super::super::provider::d2_stage("proposal_sources_validated");
        let stream = self
            .store
            .load_task_run(assignment.taskrun_id)
            .map_err(|_| {
                super::super::provider::d2_stage("proposal_error_taskrun_read");
            })?;
        if stream.current_version != current_version {
            super::super::provider::d2_stage("proposal_error_head");
            return Err(());
        }
        let task = TaskRun::replay(&stream.events).map_err(|_| ())?;
        let cycle = task.snapshot_v1().active_cycle().cloned().ok_or(())?;
        if cycle.attempt_id != assignment.attempt_id || cycle.plan_revision_ref.is_none() {
            super::super::provider::d2_stage("proposal_error_cycle");
            return Err(());
        }
        let (schema_digest, canonical_arguments, arguments_digest) =
            permission::canonical_arguments_for_mode(&call, coding)?;
        let key = ToolInvocationKey {
            taskrun_id: assignment.taskrun_id,
            attempt_id: assignment.attempt_id,
            cycle_id: cycle.cycle_id,
            proposal_index,
        };
        self.root_admission
            .admit_coding_tool_target(workspace_id, &call.tool_name, &path)
            .map_err(|_| super::super::provider::d2_stage("proposal_error_root_admission"))?;
        let permission_build::ProposalRootCapture {
            files,
            workspace_version,
            root_revision,
            root_identity,
            trust,
            target_digest: target,
            target_version,
            root_file_identity,
            project_id,
        } = permission_build::capture_proposal_root(
            &self.root_admission,
            workspace_id,
            &call.tool_name,
            &path,
            coding,
        )
        .map_err(|_| {
            super::super::provider::d2_stage("proposal_error_target_capture");
        })?;
        super::super::provider::d2_stage("proposal_target_captured");
        let trust_policy = permission::capture_current_managed_policy(
            &self.root_admission,
            workspace_id,
            trust,
            project_id,
        )
        .map_err(|_| super::super::provider::d2_stage("proposal_error_managed_policy"))?;
        let saved = self
            .store
            .load_taskrun_tool_invocation(key)
            .map_err(|_| ())?;
        let permission_scope = runne_application::permission_modes::PermissionScope {
            runtime_authority_id: self.store.runtime_authority_id().clone(),
            principal_id: principal.clone(),
            workspace_id,
        };
        let expires_at = match saved.as_ref() {
            Some(record) => record.binding.approval_expires_at,
            None => now_millis().checked_add(APPROVAL_TTL_MS).ok_or(())?,
        };
        let principal_text = principal.as_str().to_owned();
        let root_digest = IntegrityDigest::from_bytes(root_identity);
        let approval_id = stable(
            &[
                b"RUNNE_D2_TOOL_APPROVAL_ID_V1\0".as_slice(),
                assignment.taskrun_id.as_bytes().as_slice(),
                assignment.attempt_id.as_bytes().as_slice(),
                cycle.cycle_id.as_bytes().as_slice(),
                &proposal_index.to_be_bytes(),
                call.call_id.as_bytes(),
            ]
            .concat(),
        );
        let resource = format!("workspace:{}:{}", workspace_id, path);
        let helper_digest = super::permission_identity::command_helper_digest(
            self.permission_admission.as_ref().ok_or(())?,
            &call.tool_name,
        )?;
        let approval_digest = IntegrityDigest::from_bytes(approval_digest(
            assignment.taskrun_id,
            assignment.attempt_id,
            cycle.cycle_id,
            proposal_index,
            current_version,
            &call.call_id,
            &call.tool_name,
            ENVIRONMENT_REVISION,
            environment_id,
            &principal_text,
            schema_digest.as_bytes(),
            &canonical_arguments,
            target.as_ref().map(IntegrityDigest::as_bytes),
            root_digest.as_bytes(),
            root_revision,
            workspace_version,
            trust.instance_epoch,
            trust.revision,
            expires_at,
            helper_digest.as_ref().map(IntegrityDigest::as_bytes),
        ));
        let mut binding = ToolInvocationBindingV1 {
            key,
            expected_taskrun_version: current_version,
            call_id: call.call_id,
            tool_name: call.tool_name.clone(),
            tool_revision: ENVIRONMENT_REVISION.into(),
            schema_digest,
            canonical_arguments,
            arguments_digest,
            semantic_digest: IntegrityDigest::from_bytes([0; 32]),
            sources,
            environment_id: environment_id.into(),
            environment_revision: ENVIRONMENT_REVISION.into(),
            root_identity: root_digest,
            root_revision,
            target_name: path.clone(),
            target_precondition: target,
            approval_id,
            principal_id: principal_text.clone(),
            approval_principal_id: principal_text.clone(),
            approval_action: ACTION.into(),
            approval_resource: resource.clone(),
            approval_digest,
            policy_revision: POLICY_REVISION,
            approval_expires_at: expires_at,
            round_index,
        };
        binding.refresh_digests();
        let semantic_digest = binding.semantic_digest;
        let native = self.permission_admission.as_ref().ok_or_else(|| {
            super::super::provider::d2_stage("proposal_error_permission_prepare");
        })?;
        let prepared = permission::prepare_from_store(
            &self.store,
            &permission_scope,
            &principal,
            workspace_id,
            root_digest,
            trust_policy.project,
            &trust_policy.snapshot,
            &binding,
            native,
            now_millis(),
        )
        .map_err(|_| super::super::provider::d2_stage("proposal_error_permission_prepare"))?;
        permission_build::prepare_tool_helper(
            &self.store,
            &prepared,
            &binding,
            assignment,
            root_file_identity,
            target_version,
            &content,
            files,
        )
        .map_err(|_| super::super::provider::d2_stage("proposal_error_helper_prepare"))?;
        let provider = self.provider.as_ref().ok_or(())?;
        let encrypted: EncryptedToolPayloadV1 = provider
            .seal_d2_tool_arguments(
                assignment.taskrun_id,
                assignment.attempt_id,
                cycle.cycle_id,
                proposal_index,
                semantic_digest,
                &binding.canonical_arguments,
            )
            .map_err(|_| {
                super::super::provider::d2_stage("proposal_error_encrypt");
            })?;
        super::super::provider::d2_stage("proposal_encrypted");
        self.store
            .propose_taskrun_tool_invocation_with_permission(
                binding.clone(),
                encrypted,
                prepared.admission.clone(),
                assignment,
                now_millis(),
            )
            .map_err(store_error::record)?;
        super::super::provider::d2_stage("proposal_durable");
        if !prepared.requires_human
            && saved.as_ref().map(|record| record.receipt.state)
                != Some(runne_store::store::taskrun_tool_invocation::ToolInvocationState::Approved)
        {
            self.store
                .admit_taskrun_tool_permission_automatically(
                    key,
                    semantic_digest,
                    assignment,
                    now_millis(),
                )
                .map_err(|_| ())?;
        }
        drop(trust_policy);
        if prepared.requires_human {
            self.await_approval_and_execute(
                context,
                assignment,
                workspace_id,
                binding,
                principal,
                prepared,
            )
            .await
        } else {
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
            super::super::provider::d2_stage("native_effect_recorded");
            Ok(())
        }
    }
}

fn stable(bytes: &[u8]) -> [u8; 16] {
    permission::stable_tool_id(bytes)
}

fn now_millis() -> i64 {
    permission::now_millis()
}
