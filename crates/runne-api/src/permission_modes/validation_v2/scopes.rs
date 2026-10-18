use crate::permission_modes::{
    PermissionActionMapV2, PermissionActionV2, PermissionDispositionV2,
    PermissionFilesystemPostureV2, PermissionModeScopesV2, PermissionNetworkStateV2,
    PermissionProcessScopeV2,
};

use super::{PermissionModeValidationErrorV2, actions};

pub(super) fn validate(
    scopes: &PermissionModeScopesV2,
    action_map: &PermissionActionMapV2,
) -> Result<(), PermissionModeValidationErrorV2> {
    let rights = &scopes.filesystem.rights;
    if rights
        .windows(2)
        .any(|pair| pair[0].order() >= pair[1].order())
        || (scopes.filesystem.posture == PermissionFilesystemPostureV2::None && !rights.is_empty())
    {
        return Err(PermissionModeValidationErrorV2::InvalidScopes);
    }

    for (action, projection) in action_map.iter() {
        if !actions::is_actionable(projection.disposition) {
            continue;
        }
        let covered = match action {
            PermissionActionV2::FsRead
            | PermissionActionV2::FsCreate
            | PermissionActionV2::FsWrite
            | PermissionActionV2::FsDelete => {
                let Some(right) = PermissionModeScopesV2::filesystem_right_for(action) else {
                    return Err(PermissionModeValidationErrorV2::InvalidScopes);
                };
                scopes.filesystem.posture != PermissionFilesystemPostureV2::None
                    && scopes.filesystem.has_right(right)
            }
            PermissionActionV2::ProcessStart => {
                scopes.process == PermissionProcessScopeV2::ArbitraryInsideContainment
            }
            PermissionActionV2::NetworkUse => matches!(
                scopes.network,
                PermissionNetworkStateV2::Brokered | PermissionNetworkStateV2::BroadSameUser
            ),
        };
        if !covered {
            return Err(PermissionModeValidationErrorV2::InvalidScopes);
        }
    }

    if matches!(
        scopes.network,
        PermissionNetworkStateV2::None | PermissionNetworkStateV2::Unavailable
    ) && actions::is_actionable(action_map.network_use.disposition)
    {
        return Err(PermissionModeValidationErrorV2::InvalidScopes);
    }

    for (_, projection) in action_map.iter() {
        if matches!(
            projection.disposition,
            PermissionDispositionV2::Available
                | PermissionDispositionV2::RequiresExactApproval { .. }
        ) && !actions::is_operational(projection.enforcement_availability)
        {
            return Err(PermissionModeValidationErrorV2::InvalidScopes);
        }
    }
    Ok(())
}
