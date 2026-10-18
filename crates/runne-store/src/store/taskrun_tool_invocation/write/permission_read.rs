pub(super) fn load_permission(
    store: &StoreTransaction,
    key: ToolInvocationKey,
) -> Result<Option<ToolPermissionAdmissionV1>, ToolInvocationStoreError> {
    let reader = store
        .inner
        .reader
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        String,
        Vec<u8>,
        i64,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        i64,
        Vec<u8>,
        i64,
        Vec<u8>,
        i64,
    )> = reader
        .query_row(
            "SELECT runtime_authority_id,principal_id,workspace_id,selected_mode,
                    authorization_revision,managed_policy_version,managed_policy_digest,
                    composite_scope_digest,containment,native_scope_handle,decision_source,
                    relevant_policy_digest,expires_at_unix_ms
             FROM taskrun_tool_permission_admissions
             WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4",
            params![
                key.taskrun_id.as_bytes(),
                key.attempt_id.as_bytes(),
                key.cycle_id.as_bytes(),
                i64::from(key.proposal_index)
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let Some((
        runtime_authority_id,
        principal_id,
        workspace_id,
        selected_mode,
        authorization_revision,
        managed_policy_version,
        managed_policy_digest,
        composite_scope_digest,
        containment,
        native_scope_handle,
        decision_source,
        relevant_policy_digest,
        expires_at_unix_ms,
    )) = row
    else {
        return Ok(None);
    };
    Ok(Some(ToolPermissionAdmissionV1 {
        key,
        runtime_authority_id,
        principal_id,
        workspace_id: runne_domain::id::WorkspaceId::from_bytes(
            workspace_id
                .try_into()
                .map_err(|_| ToolInvocationStoreError::CorruptData)?,
        ),
        selected_mode: match selected_mode {
            1 => PermissionMode::AskAlways,
            2 => PermissionMode::RiskBased,
            3 => PermissionMode::FullAccess,
            _ => return Err(ToolInvocationStoreError::CorruptData),
        },
        authorization_revision: u64::try_from(authorization_revision)
            .map_err(|_| ToolInvocationStoreError::CorruptData)?,
        managed_policy_version: u64::try_from(managed_policy_version)
            .map_err(|_| ToolInvocationStoreError::CorruptData)?,
        managed_policy_digest: IntegrityDigest::from_bytes(
            managed_policy_digest
                .try_into()
                .map_err(|_| ToolInvocationStoreError::CorruptData)?,
        ),
        composite_scope_digest: IntegrityDigest::from_bytes(
            composite_scope_digest
                .try_into()
                .map_err(|_| ToolInvocationStoreError::CorruptData)?,
        ),
        containment: match containment {
            1 => ContainmentStrategy::WorkspaceBoundV1,
            2 => ContainmentStrategy::SameUserCompositeV1,
            3 => ContainmentStrategy::SameUserCompositeV2,
            _ => return Err(ToolInvocationStoreError::CorruptData),
        },
        native_scope_handle: IntegrityDigest::from_bytes(
            native_scope_handle
                .try_into()
                .map_err(|_| ToolInvocationStoreError::CorruptData)?,
        ),
        decision_source: ToolPermissionDecisionSource::from_tag(decision_source)
            .ok_or(ToolInvocationStoreError::CorruptData)?,
        relevant_policy_digest: IntegrityDigest::from_bytes(
            relevant_policy_digest
                .try_into()
                .map_err(|_| ToolInvocationStoreError::CorruptData)?,
        ),
        expires_at_unix_ms,
    }))
}
