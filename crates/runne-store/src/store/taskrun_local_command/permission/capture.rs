use super::capture_checks::target_matches;
pub(super) use super::capture_checks::{verify_current_selection, verify_submit_origin};
use super::{codec, owner::PermissionRootFenceRequestV1, read::LocalCommandPermissionCaptureV1};
use crate::store::{
    ManagedIdentityMetadata, PermissionModeAuthorityContext, PermissionModeSelectionSnapshot,
    StoreTransaction, taskrun_claim,
};
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1, ports::EventStoreError,
    project_trust::ProjectTrustProjectId,
};
use runne_domain::task_run::TaskRunState;
use runne_platform::local_command_linux::PermissionTargetObservationV1;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::time::{SystemTime, UNIX_EPOCH};

impl StoreTransaction {
    /// Captures one checked binding under the current T1, claim and held-root owners.
    pub fn capture_local_command_permission(
        &self,
        binding: &LocalCommandPermissionBindingV1,
        target: PermissionTargetObservationV1,
    ) -> Result<LocalCommandPermissionCaptureV1, EventStoreError> {
        let taskrun_id = binding.assignment().taskrun_id;
        let owner = self
            .inner
            .permission_owner
            .as_ref()
            .ok_or(EventStoreError::Unavailable)?;
        let project = ProjectTrustProjectId::from_bytes(*binding.project_id().as_bytes());
        let lease = owner
            .acquire_effect_lease(&self.runtime_authority_id, project)
            .map_err(|_| EventStoreError::Unavailable)?;
        let snapshot = lease.snapshot().map_err(|_| EventStoreError::Unavailable)?;
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
            ManagedIdentityMetadata::LegacyRecordV1(_) => {
                return Err(EventStoreError::CorruptData);
            }
        };
        let selection_snapshot = PermissionModeSelectionSnapshot {
            selection: current.selection.clone(),
            managed_policy_version: managed.snapshot.record.revision,
            managed_policy_digest: managed.canonical_digest,
        };
        if current.selection != *binding.selection()
            || managed.project_id != *binding.project_id().as_bytes()
            || managed.project_version != binding.project_version()
            || managed.snapshot != snapshot
            || managed.canonical_digest != binding.closed_rules_digest()
            || binding.closed_rules_snapshot() != snapshot
            || target.owner_id().iter().all(|byte| *byte == 0)
            || target.owner_generation() == 0
            || !target_matches(binding, target)
        {
            return Err(EventStoreError::CorruptData);
        }
        let selection_expires = current.selection.expires_at_unix_ms;
        let now = now_millis();
        if selection_expires.is_some_and(|expiry| expiry <= now) {
            return Err(EventStoreError::CorruptData);
        }
        let record = codec::CaptureV1::from_binding(
            binding,
            *target.owner_id(),
            target.owner_generation(),
            &selection_snapshot,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        let encoded = codec::encode(&record).map_err(|_| EventStoreError::CorruptData)?;
        let digest = codec::binding_digest(&encoded).map_err(|_| EventStoreError::CorruptData)?;
        let assignment = binding.assignment();
        let node = uuid::Uuid::parse_str(&assignment.node_id.0)
            .map_err(|_| EventStoreError::CorruptData)?;
        let fence = i64::try_from(assignment.fence.0).map_err(|_| EventStoreError::CorruptData)?;
        let node_epoch =
            i64::try_from(assignment.node_epoch).map_err(|_| EventStoreError::CorruptData)?;
        let selection_policy_version = i64::try_from(selection_snapshot.managed_policy_version)
            .map_err(|_| EventStoreError::CorruptData)?;
        let captured_at = now.max(1);
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        taskrun_claim::verify_active_assignment(&tx, assignment)
            .map_err(|_| EventStoreError::CorruptData)?;
        let stream = taskrun_claim::stream_validate::verify_stream(&tx, taskrun_id, None)
            .map_err(|_| EventStoreError::CorruptData)?;
        if stream.version != binding.claim_stream_version() || stream.state != TaskRunState::Running
        {
            return Err(EventStoreError::CorruptData);
        }
        verify_submit_origin(self, &tx, binding)?;
        verify_current_selection(&tx, &scope, &current.selection, project)?;
        let workspace: Option<(Vec<u8>, i64, i64)> = tx
            .query_row(
                "SELECT w.project_id,p.version,w.version FROM workspaces w
                 JOIN projects p ON p.project_id=w.project_id
                 JOIN workspace_identity_history h ON h.workspace_id=w.workspace_id
                 WHERE w.workspace_id=?1 AND w.principal_id=?2 AND p.principal_id=?2
                   AND w.project_id=h.project_id AND w.principal_id=h.principal_id
                   AND h.classification='canonical' AND w.open=1 AND w.live=1 AND p.archived=0",
                params![scope.workspace_id.as_bytes(), scope.principal_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| EventStoreError::CorruptData)?;
        if !workspace.is_some_and(|(project, project_version, workspace_version)| {
            project.as_slice() == binding.project_id().as_bytes()
                && u64::try_from(project_version).ok() == Some(binding.project_version())
                && u64::try_from(workspace_version).ok() == Some(binding.workspace_version())
        }) {
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
        if root.broker_root_version() != binding.admitted_root_version()
            || root.broker_root_identity() != binding.held_root_identity_digest().as_bytes()
        {
            return Err(EventStoreError::CorruptData);
        }
        let context = super::retained_context::from_capture(binding, &encoded, digest)
            .map_err(|_| EventStoreError::CorruptData)?;
        let context_bytes = super::retained_context_codec::encode(&context)
            .map_err(|_| EventStoreError::CorruptData)?;
        let context_digest = super::retained_context_codec::context_digest(&context_bytes)
            .map_err(|_| EventStoreError::CorruptData)?;
        tx.execute(
            "INSERT INTO x2_permission_bindings(
               taskrun_id,attempt_id,fence,invocation_id,binding_digest,codec_version,binding,
               native_owner_id,native_owner_generation,selection_managed_policy_version,
               selection_managed_policy_digest,captured_at,retained_context,retained_context_digest
             ) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                taskrun_id.as_bytes(),
                assignment.attempt_id.as_bytes(),
                fence,
                binding.invocation_id().as_bytes(),
                digest.as_slice(),
                encoded,
                target.owner_id().as_slice(),
                target.owner_generation().to_be_bytes().as_slice(),
                selection_policy_version,
                selection_snapshot.managed_policy_digest.as_bytes(),
                captured_at,
                context_bytes,
                context_digest.as_slice(),
            ],
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        let changed = tx
            .execute(
                "UPDATE taskrun_local_command_attempts
                 SET attempt_id=?1,node_id=?2,node_epoch=?3,fence=?4,state='approval_pending',updated_at=?5
                 WHERE taskrun_id=?6 AND state='preflight' AND attempt_id IS NULL
                   AND executable_digest IS NULL AND approval_id IS NULL
                   AND managed_area_identity IS NULL AND command_digest=?7
                   AND EXISTS(SELECT 1 FROM taskrun_local_permission_routes r
                     WHERE r.taskrun_id=taskrun_local_command_attempts.taskrun_id
                       AND r.route=2 AND r.provenance=3 AND r.cutover_version=68)",
                params![
                    assignment.attempt_id.as_bytes(),
                    node.as_bytes(),
                    node_epoch,
                    fence,
                    captured_at,
                    taskrun_id.as_bytes(),
                    binding.command_intent_digest().as_bytes(),
                ],
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        tx.commit().map_err(|_| EventStoreError::Unavailable)?;
        Ok(LocalCommandPermissionCaptureV1 {
            taskrun_id,
            attempt_id: assignment.attempt_id,
            fence: assignment.fence.0,
            invocation_id: binding.invocation_id(),
            canonical_binding_digest: *binding.digest().as_bytes(),
            binding_digest: digest,
            binding: codec::encode(&record).map_err(|_| EventStoreError::CorruptData)?,
            native_owner_id: *target.owner_id(),
            native_owner_generation: target.owner_generation(),
            state: crate::store::LocalCommandAttemptState::ApprovalPending,
        })
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}
