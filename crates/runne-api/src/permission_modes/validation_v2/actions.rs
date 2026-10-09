use crate::permission_modes::{
    PermissionActionMapV2, PermissionApprovalReasonV2, PermissionDispositionUnavailableReasonV2,
    PermissionDispositionV2, PermissionEnforcementAvailabilityV2, PermissionManagedDecisionV2,
    PermissionModeLifecycleV2, PermissionPresetBehaviorV2,
};

use super::PermissionModeValidationErrorV2;

pub(super) fn is_operational(availability: PermissionEnforcementAvailabilityV2) -> bool {
    matches!(
        availability,
        PermissionEnforcementAvailabilityV2::Native
            | PermissionEnforcementAvailabilityV2::MediatedOnly
    )
}

pub(super) fn is_actionable(disposition: PermissionDispositionV2) -> bool {
    matches!(
        disposition,
        PermissionDispositionV2::Available | PermissionDispositionV2::RequiresExactApproval { .. }
    )
}

pub(super) fn validate(
    action_map: &PermissionActionMapV2,
    lifecycle: PermissionModeLifecycleV2,
) -> Result<(), PermissionModeValidationErrorV2> {
    for (_, action) in action_map.iter() {
        let operational = is_operational(action.enforcement_availability);
        if is_actionable(action.disposition) && !operational {
            return Err(PermissionModeValidationErrorV2::InvalidActionMap);
        }
        if action.preset_behavior == PermissionPresetBehaviorV2::NoPresetPrompt
            && matches!(
                action.disposition,
                PermissionDispositionV2::RequiresExactApproval {
                    reason: PermissionApprovalReasonV2::Preset,
                }
            )
        {
            return Err(PermissionModeValidationErrorV2::InvalidActionMap);
        }
        if action.preset_behavior == PermissionPresetBehaviorV2::ExactApprovalRequired
            && action.disposition == PermissionDispositionV2::Available
        {
            return Err(PermissionModeValidationErrorV2::InvalidActionMap);
        }

        match action.managed_decision {
            PermissionManagedDecisionV2::Deny => {
                if !matches!(
                    action.disposition,
                    PermissionDispositionV2::Denied {
                        reason: crate::permission_modes::PermissionDeniedReasonV2::ManagedDeny,
                    }
                ) {
                    return Err(PermissionModeValidationErrorV2::InvalidActionMap);
                }
                continue;
            }
            PermissionManagedDecisionV2::Allow | PermissionManagedDecisionV2::Ask => {}
        }

        match lifecycle {
            PermissionModeLifecycleV2::Stale => {
                if action.disposition
                    != (PermissionDispositionV2::Unavailable {
                        reason: PermissionDispositionUnavailableReasonV2::StaleObservation,
                    })
                {
                    return Err(PermissionModeValidationErrorV2::InvalidActionMap);
                }
            }
            PermissionModeLifecycleV2::Reconciling => {
                if action.disposition
                    != (PermissionDispositionV2::Unavailable {
                        reason: PermissionDispositionUnavailableReasonV2::Reconciling,
                    })
                {
                    return Err(PermissionModeValidationErrorV2::InvalidActionMap);
                }
            }
            PermissionModeLifecycleV2::Revoked => {
                if action.disposition
                    != (PermissionDispositionV2::Denied {
                        reason: crate::permission_modes::PermissionDeniedReasonV2::Revoked,
                    })
                {
                    return Err(PermissionModeValidationErrorV2::InvalidActionMap);
                }
            }
            PermissionModeLifecycleV2::Current => {
                validate_current_action(
                    action.managed_decision,
                    action.preset_behavior,
                    action.disposition,
                    operational,
                )?;
            }
        }
    }
    Ok(())
}

fn validate_current_action(
    managed: PermissionManagedDecisionV2,
    behavior: PermissionPresetBehaviorV2,
    disposition: PermissionDispositionV2,
    operational: bool,
) -> Result<(), PermissionModeValidationErrorV2> {
    use PermissionDispositionV2 as Disposition;
    use PermissionManagedDecisionV2 as Managed;

    if matches!(
        disposition,
        Disposition::Denied {
            reason: crate::permission_modes::PermissionDeniedReasonV2::Revoked,
        }
    ) {
        return Err(PermissionModeValidationErrorV2::InvalidActionMap);
    }
    if matches!(
        disposition,
        Disposition::Denied {
            reason: crate::permission_modes::PermissionDeniedReasonV2::ManagedDeny,
        }
    ) {
        return Err(PermissionModeValidationErrorV2::InvalidActionMap);
    }
    if matches!(
        disposition,
        Disposition::RequiresExactApproval {
            reason: PermissionApprovalReasonV2::ManagedAsk
        }
    ) && managed != Managed::Ask
    {
        return Err(PermissionModeValidationErrorV2::InvalidActionMap);
    }
    if matches!(
        disposition,
        Disposition::RequiresExactApproval {
            reason: PermissionApprovalReasonV2::Preset
        }
    ) && behavior == PermissionPresetBehaviorV2::NoPresetPrompt
    {
        return Err(PermissionModeValidationErrorV2::InvalidActionMap);
    }
    if managed == Managed::Ask {
        let expected = if operational {
            Disposition::RequiresExactApproval {
                reason: PermissionApprovalReasonV2::ManagedAsk,
            }
        } else {
            match disposition {
                Disposition::Unavailable { .. } => disposition,
                _ => return Err(PermissionModeValidationErrorV2::InvalidActionMap),
            }
        };
        if disposition != expected {
            return Err(PermissionModeValidationErrorV2::InvalidActionMap);
        }
    }
    if let Disposition::Unavailable { reason } = disposition {
        match reason {
            PermissionDispositionUnavailableReasonV2::StaleObservation
                if managed != Managed::Deny =>
            {
                return Err(PermissionModeValidationErrorV2::InvalidActionMap);
            }
            PermissionDispositionUnavailableReasonV2::Reconciling if managed != Managed::Deny => {
                return Err(PermissionModeValidationErrorV2::InvalidActionMap);
            }
            _ => {}
        }
    }
    Ok(())
}
