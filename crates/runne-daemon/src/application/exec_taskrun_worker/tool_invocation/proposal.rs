use super::*;
use runne_application::ports::EventStore;
use runne_application::ports::TaskRunAssignmentIdentity;
use runne_application::ports::TaskRunAssignmentPort;
use runne_domain::{id::IntegrityDigest, task_run::TaskRun};
use runne_store::store::taskrun_tool_invocation::{
    EncryptedToolPayloadV1, ToolInvocationBindingV1, ToolInvocationKey, ToolSourceRef,
};
use sha2::{Digest, Sha256};

#[path = "proposal/approval.rs"]
mod approval;

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
        current_version: u64,
        call: runne_runtime::provider_tool::RuntimeToolCall,
        sources: Vec<ToolSourceRef>,
        workspace_id: runne_domain::id::WorkspaceId,
        principal: ApiPrincipalId,
    ) -> Result<(), ()> {
        super::super::provider::d2_stage("proposal_validating");
        let (path, _content) = parse_fixed_arguments(&call).map_err(|_| {
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
        let declarations = vec![
            runne_provider::ProviderToolDeclarationV1::for_name(
                runne_provider::ProviderToolNameV1::WorkspaceFileRead,
            ),
            runne_provider::ProviderToolDeclarationV1::for_name(
                runne_provider::ProviderToolNameV1::WorkspaceFileCreateNew,
            ),
        ];
        let schema_digest = IntegrityDigest::from_bytes(
            Sha256::digest(serde_json::to_vec(&declarations).map_err(|_| ())?).into(),
        );
        let canonical_value: serde_json::Value =
            serde_json::from_str(&call.arguments_json).map_err(|_| ())?;
        let canonical_arguments = serde_json::to_vec(&canonical_value).map_err(|_| ())?;
        let arguments_digest =
            IntegrityDigest::from_bytes(Sha256::digest(&canonical_arguments).into());
        let key = ToolInvocationKey {
            taskrun_id: assignment.taskrun_id,
            attempt_id: assignment.attempt_id,
            cycle_id: cycle.cycle_id,
            proposal_index: round_index,
        };
        self.root_admission
            .admit_d2_tool_target(workspace_id, &path)
            .map_err(|_| ())?;
        let (workspace_version, root_revision, root_identity, trust, target) = self
            .root_admission
            .with_local_command_root(workspace_id, |root, wv, _, rv, ri, admission| {
                let files = root.open_linux_command_workspace(std::path::Path::new("."))?;
                let target = crate::application::exec_taskrun_worker::local::run::tool_executor::capture_target_precondition(
                    &files,
                    &call.tool_name,
                    &path,
                ).map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)?;
                let target = target.map(|v| {
                    let bytes = serde_json::to_vec(&v).expect("version serializes");
                    IntegrityDigest::from_bytes(Sha256::digest(bytes).into())
                });
                Ok((wv, rv, ri, admission.token, target))
            })
            .map_err(|_| { super::super::provider::d2_stage("proposal_error_target_capture"); })?;
        super::super::provider::d2_stage("proposal_target_captured");
        let saved = self
            .store
            .load_taskrun_tool_invocation(key)
            .map_err(|_| ())?;
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
                &round_index.to_be_bytes(),
                call.call_id.as_bytes(),
            ]
            .concat(),
        );
        let resource = format!("workspace:{}:{}", workspace_id, path);
        let approval_digest = IntegrityDigest::from_bytes(approval_digest(
            assignment.taskrun_id,
            assignment.attempt_id,
            cycle.cycle_id,
            round_index,
            current_version,
            &call.call_id,
            &call.tool_name,
            ENVIRONMENT_REVISION,
            ENVIRONMENT_ID,
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
            environment_id: ENVIRONMENT_ID.into(),
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
        let provider = self.provider.as_ref().ok_or(())?;
        let encrypted: EncryptedToolPayloadV1 = provider
            .seal_d2_tool_arguments(
                assignment.taskrun_id,
                assignment.attempt_id,
                cycle.cycle_id,
                round_index,
                semantic_digest,
                &binding.canonical_arguments,
            )
            .map_err(|_| {
                super::super::provider::d2_stage("proposal_error_encrypt");
            })?;
        super::super::provider::d2_stage("proposal_encrypted");
        self.store
            .propose_taskrun_tool_invocation(binding.clone(), encrypted, assignment, now_millis())
            .map_err(|error| {
                use runne_store::store::taskrun_tool_invocation::ToolInvocationStoreError as E;
                super::super::provider::d2_stage(match error {
                    E::ProposalConflict(kind) => match kind {
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::Binding => "proposal_store_binding_conflict",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::Sources => "proposal_store_sources_conflict",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::DuplicateEffect => "proposal_store_duplicate_effect",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::EffectDigestToolMismatch => "proposal_store_effect_digest_tool_mismatch",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::EffectDigestArgumentsMismatch => "proposal_store_effect_digest_arguments_mismatch",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::EffectDigestTargetMismatch => "proposal_store_effect_digest_target_mismatch",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::EffectDigestRootMismatch => "proposal_store_effect_digest_root_mismatch",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::PayloadNonce => "proposal_store_payload_nonce",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::InsertUnique => "proposal_store_insert_unique",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::InsertCheck => "proposal_store_insert_check",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::InsertForeignKey => "proposal_store_insert_foreign_key",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::InsertOther => "proposal_store_insert_other",
                    },
                    E::Conflict => "proposal_store_conflict",
                    E::StaleVersion => "proposal_store_stale",
                    E::InvalidState => "proposal_store_invalid_state",
                    E::ApprovalDenied => "proposal_store_approval_denied",
                    E::ApprovalExpired => "proposal_store_approval_expired",
                    E::BudgetExhausted => "proposal_store_budget_exhausted",
                    E::Cancelled => "proposal_store_cancelled",
                    E::Uncertain => "proposal_store_uncertain",
                    E::CorruptData => "proposal_store_corrupt",
                    E::Unavailable => "proposal_store_unavailable",
                });
            })?;
        super::super::provider::d2_stage("proposal_durable");
        self.await_approval_and_execute(context, assignment, workspace_id, binding, principal)
            .await
    }
}

fn stable(bytes: &[u8]) -> [u8; 16] {
    let mut value: [u8; 16] = Sha256::digest(bytes)[..16]
        .try_into()
        .expect("fixed digest prefix");
    value[6] = (value[6] & 0x0f) | 0x70;
    value[8] = (value[8] & 0x3f) | 0x80;
    value
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}
