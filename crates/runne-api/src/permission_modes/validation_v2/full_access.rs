use crate::permission_modes::{
    PermissionActionMapV2, PermissionActionProjectionV2, PermissionActionV2,
    PermissionContainmentV2, PermissionDispositionV2, PermissionFilesystemPostureV2,
    PermissionManagedDecisionV2, PermissionModeScopesV2, PermissionNetworkStateV2,
    PermissionPresetBehaviorV2, PermissionProcessScopeV2, PermissionSourceIngressV2,
};

use super::{PermissionModeValidationErrorV2, actions};

pub(super) fn validate(
    containment: PermissionContainmentV2,
    action_map: &PermissionActionMapV2,
    scopes: &PermissionModeScopesV2,
) -> Result<(), PermissionModeValidationErrorV2> {
    if !matches!(
        containment,
        PermissionContainmentV2::SameUserCompositeV1 | PermissionContainmentV2::SameUserCompositeV2
    ) {
        return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
    }

    let actions = [
        (PermissionActionV2::FsRead, &action_map.fs_read),
        (PermissionActionV2::FsCreate, &action_map.fs_create),
        (PermissionActionV2::FsWrite, &action_map.fs_write),
        (PermissionActionV2::FsDelete, &action_map.fs_delete),
        (PermissionActionV2::ProcessStart, &action_map.process_start),
        (PermissionActionV2::NetworkUse, &action_map.network_use),
    ];
    let all_denied = actions
        .iter()
        .all(|(_, action)| action.managed_decision == PermissionManagedDecisionV2::Deny);

    for (kind, action) in actions {
        validate_action(kind, action, scopes)?;
    }

    let read_is_managed_allowed =
        action_map.fs_read.managed_decision != PermissionManagedDecisionV2::Deny;
    if read_is_managed_allowed && scopes.source_ingress != PermissionSourceIngressV2::Available {
        return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
    }

    if all_denied
        && (!actions_all_have_qualified_denial(action_map)
            || scopes.process != PermissionProcessScopeV2::None
            || scopes.network != PermissionNetworkStateV2::None
            || !matches!(
                scopes.filesystem.posture,
                PermissionFilesystemPostureV2::None | PermissionFilesystemPostureV2::BroadSameUser
            )
            || !scopes.filesystem.rights.is_empty())
    {
        return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
    }
    Ok(())
}

fn validate_action(
    kind: PermissionActionV2,
    action: &PermissionActionProjectionV2,
    scopes: &PermissionModeScopesV2,
) -> Result<(), PermissionModeValidationErrorV2> {
    if action.preset_behavior != PermissionPresetBehaviorV2::NoPresetPrompt {
        return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
    }
    let operational = actions::is_operational(action.enforcement_availability);
    let denied = action.managed_decision == PermissionManagedDecisionV2::Deny;
    if denied {
        if action.disposition
            != (PermissionDispositionV2::Denied {
                reason: crate::permission_modes::PermissionDeniedReasonV2::ManagedDeny,
            })
            || !operational
        {
            return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
        }
        let right = PermissionModeScopesV2::filesystem_right_for(kind);
        match kind {
            PermissionActionV2::FsRead
            | PermissionActionV2::FsCreate
            | PermissionActionV2::FsWrite
            | PermissionActionV2::FsDelete => {
                let Some(right) = right else {
                    return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
                };
                if scopes.filesystem.has_right(right) {
                    return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
                }
            }
            PermissionActionV2::ProcessStart => {
                if scopes.process != PermissionProcessScopeV2::None {
                    return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
                }
            }
            PermissionActionV2::NetworkUse => {
                if scopes.network != PermissionNetworkStateV2::None {
                    return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
                }
            }
        }
        return Ok(());
    }

    if !operational {
        return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
    }
    match action.managed_decision {
        PermissionManagedDecisionV2::Allow => {
            if action.disposition != PermissionDispositionV2::Available {
                return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
            }
        }
        PermissionManagedDecisionV2::Ask => {
            if action.disposition
                != (PermissionDispositionV2::RequiresExactApproval {
                    reason: crate::permission_modes::PermissionApprovalReasonV2::ManagedAsk,
                })
            {
                return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
            }
        }
        PermissionManagedDecisionV2::Deny => {
            return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
        }
    }

    match kind {
        PermissionActionV2::FsRead
        | PermissionActionV2::FsCreate
        | PermissionActionV2::FsWrite
        | PermissionActionV2::FsDelete => {
            let Some(right) = PermissionModeScopesV2::filesystem_right_for(kind) else {
                return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
            };
            if scopes.filesystem.posture != PermissionFilesystemPostureV2::BroadSameUser
                || !scopes.filesystem.has_right(right)
            {
                return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
            }
        }
        PermissionActionV2::ProcessStart => {
            if scopes.process != PermissionProcessScopeV2::ArbitraryInsideContainment {
                return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
            }
        }
        PermissionActionV2::NetworkUse => {
            if scopes.network != PermissionNetworkStateV2::BroadSameUser {
                return Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection);
            }
        }
    }
    Ok(())
}

fn actions_all_have_qualified_denial(action_map: &PermissionActionMapV2) -> bool {
    action_map.iter().all(|(_, action)| {
        action.managed_decision == PermissionManagedDecisionV2::Deny
            && matches!(
                action.disposition,
                PermissionDispositionV2::Denied {
                    reason: crate::permission_modes::PermissionDeniedReasonV2::ManagedDeny,
                }
            )
            && actions::is_operational(action.enforcement_availability)
    })
}
