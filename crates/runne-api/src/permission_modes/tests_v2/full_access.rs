use super::support::*;

#[test]
fn ready_full_rejects_bounded_filesystem_missing_path_and_brokered_network() {
    let mut bounded = full_access_allow_status();
    if let PermissionEffectiveStateV2::Ready { scopes, .. } = &mut bounded.effective {
        scopes.filesystem.posture = PermissionFilesystemPostureV2::BoundedRoots;
    }
    assert!(bounded.validate().is_err());

    let mut missing_right = full_access_allow_status();
    if let PermissionEffectiveStateV2::Ready { scopes, .. } = &mut missing_right.effective {
        scopes
            .filesystem
            .rights
            .retain(|right| *right != PermissionFilesystemRightV2::Create);
    }
    assert!(missing_right.validate().is_err());

    let mut no_process = full_access_allow_status();
    if let PermissionEffectiveStateV2::Ready { scopes, .. } = &mut no_process.effective {
        scopes.process = PermissionProcessScopeV2::None;
    }
    assert!(no_process.validate().is_err());

    let mut brokered_network = full_access_allow_status();
    if let PermissionEffectiveStateV2::Ready { scopes, .. } = &mut brokered_network.effective {
        scopes.network = PermissionNetworkStateV2::Brokered;
    }
    brokered_network.network_state = PermissionNetworkStateV2::Brokered;
    assert!(brokered_network.validate().is_err());

    let mut unavailable_network = full_access_allow_status();
    if let PermissionEffectiveStateV2::Ready { scopes, .. } = &mut unavailable_network.effective {
        scopes.network = PermissionNetworkStateV2::Unavailable;
    }
    unavailable_network.network_state = PermissionNetworkStateV2::Unavailable;
    assert!(unavailable_network.validate().is_err());
}

#[test]
fn ready_full_requires_source_ingress_for_a_managed_read_allow_or_ask() {
    let mut status = full_access_allow_status();
    if let PermissionEffectiveStateV2::Ready { scopes, .. } = &mut status.effective {
        scopes.source_ingress = PermissionSourceIngressV2::Unavailable {
            reason: PermissionSourceIngressUnavailableReasonV2::ProvenanceUnavailable,
        };
    }
    assert!(status.validate().is_err());

    let mut ask_read = full_access_allow_status();
    if let PermissionEffectiveStateV2::Ready {
        action_map, scopes, ..
    } = &mut ask_read.effective
    {
        action_map.fs_read = action(
            PermissionManagedDecisionV2::Ask,
            PermissionPresetBehaviorV2::NoPresetPrompt,
            PermissionEnforcementAvailabilityV2::Native,
        );
        scopes.source_ingress = PermissionSourceIngressV2::Unavailable {
            reason: PermissionSourceIngressUnavailableReasonV2::ProvenanceUnavailable,
        };
    }
    assert!(ask_read.validate().is_err());
}

#[test]
fn managed_denied_omissions_and_all_denied_empty_scopes_can_be_ready_full() {
    let mut mixed = full_access_allow_status();
    if let PermissionEffectiveStateV2::Ready {
        action_map, scopes, ..
    } = &mut mixed.effective
    {
        action_map.fs_read = action(
            PermissionManagedDecisionV2::Deny,
            PermissionPresetBehaviorV2::NoPresetPrompt,
            PermissionEnforcementAvailabilityV2::Native,
        );
        scopes
            .filesystem
            .rights
            .retain(|right| *right != PermissionFilesystemRightV2::Read);
        scopes.source_ingress = PermissionSourceIngressV2::Unavailable {
            reason: PermissionSourceIngressUnavailableReasonV2::CurrentEvidenceUnavailable,
        };
    }
    assert_eq!(mixed.validate(), Ok(()));

    let none = full_access_all_deny_status();
    assert_eq!(none.validate(), Ok(()));

    let mut broad_empty = full_access_all_deny_status();
    if let PermissionEffectiveStateV2::Ready { scopes, .. } = &mut broad_empty.effective {
        scopes.filesystem.posture = PermissionFilesystemPostureV2::BroadSameUser;
    }
    assert_eq!(broad_empty.validate(), Ok(()));

    let mut missing_deny_enforcement = full_access_all_deny_status();
    if let PermissionEffectiveStateV2::Ready { action_map, .. } =
        &mut missing_deny_enforcement.effective
    {
        action_map.network_use.enforcement_availability =
            PermissionEnforcementAvailabilityV2::Unavailable {
                reason: PermissionEnforcementUnavailableReasonV2::NativeContainmentUnavailable,
            };
    }
    assert_eq!(
        missing_deny_enforcement.validate(),
        Err(PermissionModeValidationErrorV2::InvalidFullAccessProjection)
    );
}

#[test]
fn mediated_create_can_be_available_while_full_projection_remains_not_ready() {
    let mut actions = all_actions(action(
        PermissionManagedDecisionV2::Deny,
        PermissionPresetBehaviorV2::NoPresetPrompt,
        PermissionEnforcementAvailabilityV2::Native,
    ));
    actions.fs_create = action(
        PermissionManagedDecisionV2::Allow,
        PermissionPresetBehaviorV2::NoPresetPrompt,
        PermissionEnforcementAvailabilityV2::MediatedOnly,
    );
    let scopes = PermissionModeScopesV2 {
        filesystem: PermissionFilesystemScopeV2 {
            posture: PermissionFilesystemPostureV2::BoundedRoots,
            rights: vec![PermissionFilesystemRightV2::Create],
        },
        process: PermissionProcessScopeV2::None,
        network: PermissionNetworkStateV2::None,
        source_ingress: PermissionSourceIngressV2::Unavailable {
            reason: PermissionSourceIngressUnavailableReasonV2::CurrentEvidenceUnavailable,
        },
    };
    let status = not_ready_status(
        PermissionModeV1::FullAccess,
        PermissionModeNotReadyReasonV2::CompositePolicyUnenforceable,
        PermissionModeLifecycleV2::Current,
        actions,
        scopes,
    );
    assert_eq!(status.validate(), Ok(()));
    let PermissionEffectiveStateV2::NotReady {
        action_map, scopes, ..
    } = status.effective
    else {
        panic!("incomplete Full projection was reported Ready");
    };
    assert_eq!(
        action_map.fs_create.disposition,
        PermissionDispositionV2::Available
    );
    assert_eq!(scopes.process, PermissionProcessScopeV2::None);
    assert_eq!(scopes.network, PermissionNetworkStateV2::None);
}
