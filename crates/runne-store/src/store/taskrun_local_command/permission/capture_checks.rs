use crate::store::StoreTransaction;
use runne_application::{
    permission_modes::{LocalCommandPermissionBindingV1, PermissionMode, PermissionScope},
    ports::EventStoreError,
    project_trust::ProjectTrustProjectId,
};
use runne_platform::local_command_linux::PermissionTargetObservationV1;
use rusqlite::{OptionalExtension, params};

pub(super) fn verify_submit_origin(
    store: &StoreTransaction,
    tx: &rusqlite::Transaction<'_>,
    binding: &LocalCommandPermissionBindingV1,
) -> Result<(), EventStoreError> {
    let origin = crate::store::taskrun_submit_origin::verify_submitted_v2_origin(
        tx,
        binding.assignment().taskrun_id,
        &store.runtime_authority_id,
    )
    .map_err(|_| EventStoreError::CorruptData)?
    .ok_or(EventStoreError::CorruptData)?;
    let command = origin.input.local_command();
    if origin.workspace_id != binding.selection().scope.workspace_id
        || origin.principal_id.0.as_str() != binding.selection().scope.principal_id.as_str()
        || origin.project_id != Some(binding.project_id())
        || command != Some(binding.command())
        || command.map(|value| value.intent_digest())
            != Some(*binding.command_intent_digest().as_bytes())
    {
        return Err(EventStoreError::CorruptData);
    }
    Ok(())
}

pub(super) fn verify_current_selection(
    tx: &rusqlite::Transaction<'_>,
    scope: &PermissionScope,
    selection: &runne_application::permission_modes::ModeSelection,
    project: ProjectTrustProjectId,
) -> Result<(), EventStoreError> {
    type SelectionRow = (Vec<u8>, i64, i64, i64, Option<i64>);
    let row: Option<SelectionRow> = tx
        .query_row(
            "SELECT project_id,selected_mode,preset_version,authorization_revision,expires_at_unix_ms
             FROM permission_mode_selections
             WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3",
            params![scope.runtime_authority_id.0,scope.principal_id.as_str(),scope.workspace_id.as_bytes()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    match row {
        None if selection.selected_mode == PermissionMode::AskAlways
            && selection.authorization_revision == 0
            && selection.preset_version.as_u16() == 1
            && selection.expires_at_unix_ms.is_none() =>
        {
            Ok(())
        }
        Some((saved_project, mode, preset, revision, expires))
            if saved_project.as_slice() == project.as_bytes()
                && mode == mode_tag(selection.selected_mode)
                && preset == i64::from(selection.preset_version.as_u16())
                && u64::try_from(revision).ok() == Some(selection.authorization_revision)
                && expires == selection.expires_at_unix_ms =>
        {
            Ok(())
        }
        _ => Err(EventStoreError::CorruptData),
    }
}

pub(super) fn target_matches(
    binding: &LocalCommandPermissionBindingV1,
    target: PermissionTargetObservationV1,
) -> bool {
    let approval = binding.approval();
    approval.normalized_arguments_digest.as_bytes() == target.normalized_arguments_digest()
        && approval.tool_schema_digest.as_bytes() == target.schema_digest()
        && approval.target_identity_digest.as_bytes() == target.target_identity()
        && approval.target_version == target.target_version()
        && approval.environment_digest.as_bytes() == target.environment_digest()
        && approval.cwd_identity_digest.as_bytes() == target.cwd_identity()
        && approval.executable_digest.map(|value| *value.as_bytes())
            == Some(*target.executable_digest())
}

pub(super) const fn mode_tag(mode: PermissionMode) -> i64 {
    match mode {
        PermissionMode::AskAlways => 1,
        PermissionMode::RiskBased => 2,
        PermissionMode::FullAccess => 3,
    }
}
