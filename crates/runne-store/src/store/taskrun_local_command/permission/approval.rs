use super::{
    capture, codec,
    model::{now_ms, proof_digest, verify_approval},
    owner::PermissionRootFenceRequestV1,
};
use crate::store::{
    ManagedIdentityMetadata, PermissionModeAuthorityContext, StoreTransaction, taskrun_claim,
};
use runne_application::{
    permission_modes::{
        ManagedDisposition, ManagedPolicyEvaluation, NativeScopeAdmissionReceipt, PermissionAction,
        PermissionPolicyCompiler, PolicyDecision, PolicyEvaluationInput, ResolutionState,
        ResourceFacts, Sensitivity, SizeBound, TargetState, WorkspaceRelation,
        admit_effective_mode, admit_invocation_scope,
    },
    ports::EventStoreError,
    project_trust::{ManagedEffectDecision, ProjectTrustProjectId},
};
use runne_domain::id::ApprovalId;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

type SavedPermissionBindingRow = (Vec<u8>, Vec<u8>, String, Option<Vec<u8>>, Option<i64>);

impl StoreTransaction {
    /// Mints current native admission and records the exact auto or human decision.
    pub fn admit_local_command_permission(
        &self,
        binding: &runne_application::permission_modes::LocalCommandPermissionBindingV1,
        approval_id: Option<ApprovalId>,
    ) -> Result<NativeScopeAdmissionReceipt, EventStoreError> {
        let taskrun_id = binding.assignment().taskrun_id;
        let project = ProjectTrustProjectId::from_bytes(*binding.project_id().as_bytes());
        let owner = self
            .inner
            .permission_owner
            .as_ref()
            .ok_or(EventStoreError::Unavailable)?;
        let lease = owner
            .acquire_effect_lease(&self.runtime_authority_id, project)
            .map_err(|_| EventStoreError::Unavailable)?;
        let trust = lease.snapshot().map_err(|_| EventStoreError::Unavailable)?;
        let scope = binding.selection().scope.clone();
        let authority =
            PermissionModeAuthorityContext::new(&scope.principal_id, project, lease.as_ref(), None);
        let current = self
            .load_permission_mode_selection_with_managed_identity(
                &scope,
                &scope.principal_id,
                &authority,
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let managed = match current.identity {
            ManagedIdentityMetadata::ClosedRulesV2(value) => value,
            ManagedIdentityMetadata::LegacyRecordV1(_) => return Err(EventStoreError::CorruptData),
        };
        if current.selection != *binding.selection()
            || managed.snapshot != trust
            || managed.snapshot != binding.closed_rules_snapshot()
            || managed.canonical_digest != binding.closed_rules_digest()
            || current
                .selection
                .expires_at_unix_ms
                .is_some_and(|expiry| expiry <= now_ms())
        {
            return Err(EventStoreError::CorruptData);
        }
        let managed_decision = binding
            .scope()
            .managed_policy
            .scope_minimum_disposition(binding.scope())
            .ok_or(EventStoreError::CorruptData)?;
        let disposition = match managed_decision {
            ManagedEffectDecision::Allow => ManagedDisposition::Allow,
            ManagedEffectDecision::Ask => ManagedDisposition::Ask,
            ManagedEffectDecision::Deny => ManagedDisposition::Deny,
        };
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        taskrun_claim::verify_active_assignment(&tx, binding.assignment())
            .map_err(|_| EventStoreError::CorruptData)?;
        let stream = taskrun_claim::stream_validate::verify_stream(&tx, taskrun_id, None)
            .map_err(|_| EventStoreError::CorruptData)?;
        if stream.version != binding.claim_stream_version()
            || stream.state != runne_domain::task_run::TaskRunState::Running
        {
            return Err(EventStoreError::CorruptData);
        }
        capture::verify_submit_origin(self, &tx, binding)?;
        capture::verify_current_selection(&tx, &scope, &current.selection, project)?;
        let saved: Option<SavedPermissionBindingRow> = tx
            .query_row(
                "SELECT b.binding_digest,b.binding,a.state,a.attempt_id,a.fence
             FROM x2_permission_bindings b JOIN taskrun_local_command_attempts a USING(taskrun_id)
             WHERE b.taskrun_id=?1 AND b.attempt_id=?2 AND b.fence=?3",
                params![
                    taskrun_id.as_bytes(),
                    binding.assignment().attempt_id.as_bytes(),
                    binding.assignment().fence.0 as i64
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| EventStoreError::CorruptData)?;
        let Some((digest, bytes, state, attempt, fence)) = saved else {
            return Err(EventStoreError::CorruptData);
        };
        let record = codec::decode(&bytes).map_err(|_| EventStoreError::CorruptData)?;
        if !codec::digest_matches(&bytes, &digest)
            || record.canonical_binding_digest != *binding.digest().as_bytes()
            || attempt.as_deref() != Some(binding.assignment().attempt_id.as_bytes())
            || fence != Some(binding.assignment().fence.0 as i64)
            || state != "approval_pending"
        {
            return Err(EventStoreError::CorruptData);
        }
        let root_request = PermissionRootFenceRequestV1::new(
            scope.workspace_id,
            binding.workspace_version(),
            binding.admitted_root_version(),
            *binding.held_root_identity_digest().as_bytes(),
        );
        let root = owner
            .acquire_root_fence(&self.runtime_authority_id, &root_request)
            .map_err(|_| EventStoreError::CorruptData)?;
        let preparation = self.local_permission_preparation()?;
        let admission_port = preparation.invocation_scope_admission_port();
        let effective = admit_effective_mode(
            current.selection.selected_mode,
            current.selection.preset_version,
            binding.scope(),
            admission_port,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        let native = admit_invocation_scope(binding.scope(), admission_port)
            .map_err(|_| EventStoreError::CorruptData)?;
        let scope_digest = binding
            .scope()
            .digest()
            .map_err(|_| EventStoreError::CorruptData)?;
        let approved_at = approval_id
            .map(|id| verify_approval(&tx, binding, id, false))
            .transpose()?;
        let candidate = binding.approval().clone();
        let decision = PermissionPolicyCompiler::compile(&PolicyEvaluationInput {
            selection: current.selection.clone(),
            effective_scope: binding.scope().clone(),
            effective,
            invocation: runne_application::permission_modes::InvocationPolicyRequest {
                action: PermissionAction::ProcessStart,
                resource: ResourceFacts {
                    workspace: WorkspaceRelation::Inside,
                    sensitivity: Sensitivity::Unknown,
                    size: SizeBound::Unknown,
                    resolution: ResolutionState::HeldSafe,
                    resolved_path: None,
                    target: TargetState::Unknown,
                    object: runne_application::permission_modes::ObjectKind::Unknown,
                    executable: true,
                },
                composite_scope: binding.scope().clone(),
                candidate_binding: candidate.clone(),
                approved_binding: approved_at.map(|_| candidate),
                native_admission: Some(native),
            },
            managed: ManagedPolicyEvaluation {
                scope_digest,
                policy_digest: binding.scope().managed_policy.policy_digest(),
                disposition,
            },
            now_unix_ms: now_ms(),
        });
        let human = match decision {
            PolicyDecision::Allow {
                native_admission, ..
            } if native_admission == native => approval_id.is_some(),
            _ => return Err(EventStoreError::CorruptData),
        };
        if human != approval_id.is_some()
            || root.broker_root_version() != binding.admitted_root_version()
            || root.broker_root_identity() != binding.held_root_identity_digest().as_bytes()
        {
            return Err(EventStoreError::CorruptData);
        }
        let proof = if let (Some(id), Some(accepted_at)) = (approval_id, approved_at) {
            let proof = proof_digest(taskrun_id, binding, id, accepted_at);
            tx.execute(
                "INSERT INTO x2_permission_human(taskrun_id,attempt_id,binding_digest,proof_digest,approval_digest,approval_id,accepted_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![taskrun_id.as_bytes(), binding.assignment().attempt_id.as_bytes(), digest,
                    proof.as_slice(), binding.approval().digest().as_bytes(), id.as_bytes(), accepted_at],
            ).map_err(|_| EventStoreError::CorruptData)?;
            Some(proof)
        } else {
            None
        };
        tx.execute(
            "INSERT INTO x2_permission_admission(taskrun_id,attempt_id,binding_digest,admission_kind,proof_digest,admitted_at)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![taskrun_id.as_bytes(), binding.assignment().attempt_id.as_bytes(), digest,
                if human { 2 } else { 1 }, proof.as_ref().map(|value| value.as_slice()), now_ms().max(1)],
        ).map_err(|_| EventStoreError::CorruptData)?;
        let changed = tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='approved',updated_at=?1
             WHERE taskrun_id=?2 AND attempt_id=?3 AND fence=?4 AND state='approval_pending'
               AND executable_digest IS NULL AND approval_id IS NULL AND managed_area_identity IS NULL",
            params![now_ms(), taskrun_id.as_bytes(), binding.assignment().attempt_id.as_bytes(), binding.assignment().fence.0 as i64],
        ).map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        tx.commit().map_err(|_| EventStoreError::Unavailable)?;
        Ok(native)
    }
}
