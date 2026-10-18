use runne_application::permission_modes::{ContainmentStrategy, PermissionMode};

use super::model::MISSING_PERMISSION_MODE_MANAGED_DIGEST;
const MISSING_SELECTION_MANAGED_DIGEST: [u8; 32] = MISSING_PERMISSION_MODE_MANAGED_DIGEST;
type StoredPermissionModeSelection = (i64, i64, Vec<u8>, i64, Option<i64>);

pub(super) fn insert_permission(
    tx: &rusqlite::Transaction<'_>,
    binding: &ToolInvocationBindingV1,
    permission: &ToolPermissionAdmissionV1,
    now: i64,
) -> Result<(), ToolInvocationStoreError> {
    validate_permission(binding, permission, now)?;
    let changed = tx
        .execute(
            "INSERT INTO taskrun_tool_permission_admissions(
               taskrun_id,attempt_id,cycle_id,proposal_index,runtime_authority_id,principal_id,
               workspace_id,selected_mode,preset_version,authorization_revision,
               managed_policy_version,managed_policy_digest,composite_scope_digest,containment,
               native_scope_handle,decision_source,relevant_policy_digest,expires_at_unix_ms,
               created_at_unix_ms
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                permission.key.taskrun_id.as_bytes(),
                permission.key.attempt_id.as_bytes(),
                permission.key.cycle_id.as_bytes(),
                i64::from(permission.key.proposal_index),
                permission.runtime_authority_id,
                permission.principal_id,
                permission.workspace_id.as_bytes(),
                mode_tag(permission.selected_mode),
                permission.authorization_revision as i64,
                permission.managed_policy_version as i64,
                permission.managed_policy_digest.as_bytes(),
                permission.composite_scope_digest.as_bytes(),
                containment_tag(permission.containment),
                permission.native_scope_handle.as_bytes(),
                permission.decision_source.tag(),
                permission.relevant_policy_digest.as_bytes(),
                permission.expires_at_unix_ms,
                now
            ],
        )
        .map_err(|_| {
            ToolInvocationStoreError::ProposalConflict(ProposalConflictKind::InsertOther)
        })?;
    if changed != 1 {
        return Err(ToolInvocationStoreError::Conflict);
    }
    Ok(())
}

pub(super) fn validate_release_permission(
    tx: &rusqlite::Connection,
    runtime_authority: &str,
    binding: &ToolInvocationBindingV1,
    now: i64,
) -> Result<ToolPermissionDecisionSource, ToolInvocationStoreError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(String, String, i64, i64, Vec<u8>, i64, i64)> = tx
        .query_row(
            "SELECT p.runtime_authority_id,p.principal_id,p.authorization_revision,
                    p.managed_policy_version,p.managed_policy_digest,p.selected_mode,p.decision_source
             FROM taskrun_tool_permission_admissions p
             WHERE p.taskrun_id=?1 AND p.attempt_id=?2 AND p.cycle_id=?3 AND p.proposal_index=?4",
            params![
                binding.key.taskrun_id.as_bytes(),
                binding.key.attempt_id.as_bytes(),
                binding.key.cycle_id.as_bytes(),
                i64::from(binding.key.proposal_index)
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
                ))
            },
        )
        .optional()
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let Some((authority, principal, revision, managed_version, managed_digest, selected, source)) =
        row
    else {
        return Err(ToolInvocationStoreError::InvalidState);
    };
    let source = ToolPermissionDecisionSource::from_tag(source)
        .ok_or(ToolInvocationStoreError::CorruptData)?;
    if authority != runtime_authority
        || principal != binding.principal_id
        || now >= binding.approval_expires_at
    {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let current: Option<StoredPermissionModeSelection> = tx
        .query_row(
            "SELECT authorization_revision,managed_policy_version,managed_policy_digest,
                    selected_mode,expires_at_unix_ms FROM permission_mode_selections
             WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=(
               SELECT workspace_id FROM taskrun_tool_permission_admissions
               WHERE taskrun_id=?3 AND attempt_id=?4 AND cycle_id=?5 AND proposal_index=?6
             )",
            params![
                authority,
                principal,
                binding.key.taskrun_id.as_bytes(),
                binding.key.attempt_id.as_bytes(),
                binding.key.cycle_id.as_bytes(),
                i64::from(binding.key.proposal_index)
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
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let expected = current.unwrap_or((0, 0, MISSING_SELECTION_MANAGED_DIGEST.to_vec(), 1, None));
    if revision != expected.0
        || managed_version != expected.1
        || managed_digest != expected.2
        || selected != expected.3
        || expected.4.is_some_and(|expires_at| now >= expires_at)
    {
        return Err(ToolInvocationStoreError::Conflict);
    }
    Ok(source)
}

pub(super) fn admit_automatically(
    s: &StoreTransaction,
    key: ToolInvocationKey,
    semantic_digest: IntegrityDigest,
    assignment: &TaskRunAssignmentIdentity,
    _now: i64,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    let mut writer = s
        .inner
        .writer
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let tx = writer
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let now = validate::fresh_now_millis();
    let binding = load_binding_for_validation(&tx, key)?;
    same_assignment(key, assignment)?;
    if binding.semantic_digest != semantic_digest {
        return Err(ToolInvocationStoreError::Conflict);
    }
    validate_task(
        &tx,
        &s.runtime_authority_id,
        assignment,
        binding.expected_taskrun_version,
        key.cycle_id,
        key.proposal_index,
        &binding.principal_id,
        now,
    )?;
    if validate_release_permission(&tx, &s.runtime_authority_id.0, &binding, now)?
        != ToolPermissionDecisionSource::AutoPreset
    {
        return Err(ToolInvocationStoreError::ApprovalDenied);
    }
    let old = read::get_from_connection(&tx, key)?.ok_or(ToolInvocationStoreError::InvalidState)?;
    if old.state != ToolInvocationState::Proposed {
        return Err(ToolInvocationStoreError::InvalidState);
    }
    tx.execute(
        "UPDATE taskrun_tool_invocations SET state='approved',updated_at=?1
         WHERE taskrun_id=?2 AND attempt_id=?3 AND cycle_id=?4 AND proposal_index=?5
           AND state='proposed' AND semantic_digest=?6",
        params![
            now,
            key.taskrun_id.as_bytes(),
            key.attempt_id.as_bytes(),
            key.cycle_id.as_bytes(),
            i64::from(key.proposal_index),
            semantic_digest.as_bytes()
        ],
    )
    .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let result =
        read::get_from_connection(&tx, key)?.ok_or(ToolInvocationStoreError::CorruptData)?;
    if result.state != ToolInvocationState::Approved {
        return Err(ToolInvocationStoreError::InvalidState);
    }
    tx.commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    Ok(result)
}

fn validate_permission(
    binding: &ToolInvocationBindingV1,
    permission: &ToolPermissionAdmissionV1,
    now: i64,
) -> Result<(), ToolInvocationStoreError> {
    if permission.key != binding.key
        || permission.principal_id != binding.principal_id
        || permission.runtime_authority_id.is_empty()
        || permission.runtime_authority_id.len() > 256
        || permission.authorization_revision > i64::MAX as u64
        || permission.managed_policy_version > i64::MAX as u64
        || now >= permission.expires_at_unix_ms
        || permission.expires_at_unix_ms != binding.approval_expires_at
        || permission
            .native_scope_handle
            .as_bytes()
            .iter()
            .all(|b| *b == 0)
        || permission
            .composite_scope_digest
            .as_bytes()
            .iter()
            .all(|b| *b == 0)
    {
        return Err(ToolInvocationStoreError::Conflict);
    }
    Ok(())
}

fn mode_tag(mode: PermissionMode) -> i64 {
    match mode {
        PermissionMode::AskAlways => 1,
        PermissionMode::RiskBased => 2,
        PermissionMode::FullAccess => 3,
    }
}

fn containment_tag(strategy: ContainmentStrategy) -> i64 {
    match strategy {
        ContainmentStrategy::WorkspaceBoundV1 => 1,
        ContainmentStrategy::SameUserCompositeV1 => 2,
        ContainmentStrategy::SameUserCompositeV2 => 3,
    }
}

#[cfg(test)]
mod containment_tag_tests {
    use super::containment_tag;
    use runne_application::permission_modes::ContainmentStrategy;

    #[test]
    fn legacy_strategy_tags_stay_fixed_and_v2_uses_three() {
        assert_eq!(containment_tag(ContainmentStrategy::WorkspaceBoundV1), 1);
        assert_eq!(containment_tag(ContainmentStrategy::SameUserCompositeV1), 2);
        assert_eq!(containment_tag(ContainmentStrategy::SameUserCompositeV2), 3);
    }
}

#[cfg(test)]
#[path = "permission/tests.rs"]
mod tests;

include!("permission/managed.rs");
include!("permission_observation.rs");
