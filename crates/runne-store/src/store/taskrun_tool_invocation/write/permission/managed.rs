use runne_application::project_trust::{
    ManagedEffectClass, ManagedEffectDecision, ProjectTrustEffectPolicySnapshot,
    ProjectTrustProjectId, ProjectTrustStatus, SourceChannel,
};

struct StoreOwnedCurrentPolicy {
    project: ProjectTrustProjectId,
    workspace_id: runne_domain::id::WorkspaceId,
    workspace_version: u64,
    principal_id: String,
    admission: ToolPermissionAdmissionV1,
    snapshot: ProjectTrustEffectPolicySnapshot,
    digest: runne_domain::id::IntegrityDigest,
    _lease: Box<dyn runne_application::project_trust::ProjectTrustEffectLease>,
}

fn acquire_store_owned_current_policy(
    store: &StoreTransaction,
    key: ToolInvocationKey,
) -> Result<StoreOwnedCurrentPolicy, ToolInvocationStoreError> {
    let owner = store
        .inner
        .permission_owner
        .as_ref()
        .ok_or(ToolInvocationStoreError::Unavailable)?;
    let admission = load_permission(store, key)?.ok_or(ToolInvocationStoreError::InvalidState)?;
    let workspace: Option<(i64, Vec<u8>)> = {
        let reader = store
            .inner
            .reader
            .lock()
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        reader
            .query_row(
                "SELECT w.version,w.project_id FROM workspaces w JOIN projects p
                   ON p.project_id=w.project_id
                 WHERE w.workspace_id=?1 AND w.principal_id=?2
                   AND w.live=1 AND w.open=1 AND p.archived=0",
                params![admission.workspace_id.as_bytes(), admission.principal_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ToolInvocationStoreError::CorruptData)?
    };
    let (workspace_version, project_bytes) = workspace.ok_or(ToolInvocationStoreError::Conflict)?;
    let workspace_version =
        u64::try_from(workspace_version).map_err(|_| ToolInvocationStoreError::CorruptData)?;
    if workspace_version == 0 {
        return Err(ToolInvocationStoreError::CorruptData);
    }
    let project = ProjectTrustProjectId::from_bytes(
        project_bytes
            .try_into()
            .map_err(|_| ToolInvocationStoreError::CorruptData)?,
    );
    let lease = owner
        .acquire_effect_lease(&store.runtime_authority_id, project)
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let snapshot = lease
        .snapshot()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let digest =
        runne_application::project_trust::managed_effect_policy_digest_v2(project, &snapshot)
            .map(runne_domain::id::IntegrityDigest::from_bytes)
            .ok_or(ToolInvocationStoreError::CorruptData)?;
    Ok(StoreOwnedCurrentPolicy {
        project,
        workspace_id: admission.workspace_id,
        workspace_version,
        principal_id: admission.principal_id.clone(),
        admission,
        snapshot,
        digest,
        _lease: lease,
    })
}

fn validate_current_workspace_project(
    tx: &rusqlite::Transaction<'_>,
    current: &StoreOwnedCurrentPolicy,
) -> Result<(), ToolInvocationStoreError> {
    let workspace: Option<(i64, Vec<u8>)> = tx
        .query_row(
            "SELECT w.version,w.project_id FROM workspaces w JOIN projects p
               ON p.project_id=w.project_id
             WHERE w.workspace_id=?1 AND w.principal_id=?2
               AND w.live=1 AND w.open=1 AND p.archived=0",
            params![current.workspace_id.as_bytes(), current.principal_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    if !workspace.is_some_and(|(version, project)| {
        version == current.workspace_version as i64
            && project.as_slice() == current.project.as_bytes()
    }) {
        return Err(ToolInvocationStoreError::Conflict);
    }
    Ok(())
}

fn validate_current_managed_effect_policy(
    tx: &rusqlite::Transaction<'_>,
    key: ToolInvocationKey,
    binding: &ToolInvocationBindingV1,
    snapshot: &ProjectTrustEffectPolicySnapshot,
    current_digest: runne_domain::id::IntegrityDigest,
) -> Result<(), ToolInvocationStoreError> {
    if !snapshot.is_valid()
        || snapshot.record.revision == 0
        || snapshot.record.status == ProjectTrustStatus::Untrusted
        || snapshot.record.managed_deny_mask
            & (SourceChannel::Helpers.mask_bit() | SourceChannel::FilesRead.mask_bit())
            != 0
    {
        return Err(ToolInvocationStoreError::ApprovalDenied);
    }
    let admission: Option<(Vec<u8>, i64)> = tx
        .query_row(
            "SELECT relevant_policy_digest,decision_source
             FROM taskrun_tool_permission_admissions
             WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4",
            params![
                key.taskrun_id.as_bytes(),
                key.attempt_id.as_bytes(),
                key.cycle_id.as_bytes(),
                i64::from(key.proposal_index)
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let Some((saved_digest, source)) = admission else {
        return Err(ToolInvocationStoreError::InvalidState);
    };
    if saved_digest.as_slice() != current_digest.as_bytes() {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let source = ToolPermissionDecisionSource::from_tag(source)
        .ok_or(ToolInvocationStoreError::CorruptData)?;
    let classes: &[ManagedEffectClass] = match binding.tool_name.as_str() {
        "workspace.file.read" => &[ManagedEffectClass::FsRead],
        "workspace.file.create_new" => &[
            ManagedEffectClass::FsRead,
            ManagedEffectClass::FsCreate,
            ManagedEffectClass::FsWrite,
        ],
        _ => return Err(ToolInvocationStoreError::ApprovalDenied),
    };
    let mut requires_human = false;
    for class in classes {
        match snapshot.policy.decision_for(*class) {
            ManagedEffectDecision::Deny => return Err(ToolInvocationStoreError::ApprovalDenied),
            ManagedEffectDecision::Ask => requires_human = true,
            ManagedEffectDecision::Allow => {}
        }
    }
    if requires_human && source != ToolPermissionDecisionSource::Human {
        return Err(ToolInvocationStoreError::ApprovalDenied);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_helper_child(
    child: &runne_platform::local_command_linux::PermissionHelperChildV1<'_>,
    binding: &ToolInvocationBindingV1,
    permission: &ToolPermissionAdmissionV1,
    assignment: &TaskRunAssignmentIdentity,
    workspace_id: runne_domain::id::WorkspaceId,
) -> Result<(), ToolInvocationStoreError> {
    use runne_platform::local_command_linux::PermissionHelperOperationV1 as Operation;

    let observation = child.observation();
    let helper = observation.binding();
    let operation_matches = match binding.tool_name.as_str() {
        "workspace.file.read" => observation.operation() == Operation::Read,
        "workspace.file.create_new" => observation.operation() == Operation::CreateNew,
        _ => false,
    };
    let target_digest = observation.target_version().map(|target| {
        #[derive(serde::Serialize)]
        struct VersionV1 {
            device: u64,
            inode: u64,
            size: u64,
            mtime_sec: i64,
            mtime_nsec: i64,
            ctime_sec: i64,
            ctime_nsec: i64,
        }
        let target = VersionV1 {
            device: target.device,
            inode: target.inode,
            size: target.size,
            mtime_sec: target.mtime_sec,
            mtime_nsec: target.mtime_nsec,
            ctime_sec: target.ctime_sec,
            ctime_nsec: target.ctime_nsec,
        };
        runne_domain::id::IntegrityDigest::from_bytes(
            sha2::Sha256::digest(serde_json::to_vec(&target).expect("version serializes")).into(),
        )
    });
    let receipt = child.native_receipt();
    if child.was_released()
        || !operation_matches
        || observation.path() != binding.target_name
        || observation.arguments_digest() != binding.arguments_digest.as_bytes()
        || target_digest != binding.target_precondition
        || helper.taskrun_id != binding.key.taskrun_id.to_string()
        || helper.attempt_id != binding.key.attempt_id.to_string()
        || helper.cycle_id != binding.key.cycle_id.to_string()
        || helper.proposal_index != binding.key.proposal_index
        || helper.taskrun_version != binding.expected_taskrun_version
        || helper.assignment_fence != assignment.fence.0
        || helper.invocation_digest != binding.semantic_digest.to_string()
        || helper.environment_digest != environment_digest(binding)
        || helper.approval_digest != binding.approval_digest.to_string()
        || Some(helper.expires_at_unix_ms) != u64::try_from(binding.approval_expires_at).ok()
        || permission.key != binding.key
        || permission.workspace_id != workspace_id
        || receipt.platform_handle_id() != permission.native_scope_handle
        || receipt.scope_digest().as_bytes() != permission.composite_scope_digest.as_bytes()
        || receipt.managed_policy_digest() != permission.relevant_policy_digest
        || receipt.containment() != permission.containment
    {
        return Err(ToolInvocationStoreError::Conflict);
    }
    Ok(())
}

fn environment_digest(binding: &ToolInvocationBindingV1) -> String {
    format!(
        "{:x}",
        sha2::Sha256::digest(
            format!(
                "{}\0{}",
                binding.environment_id, binding.environment_revision
            )
            .as_bytes()
        )
    )
}
