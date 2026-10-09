use super::support::*;

#[test]
fn action_map_has_exact_six_camel_case_classes() {
    let value = serde_json::to_value(full_access_allow_status()).expect("status JSON");
    let map = value["effective"]["actionMap"]
        .as_object()
        .expect("fixed action map");
    let keys = map.keys().map(String::as_str).collect::<Vec<_>>();
    assert_eq!(
        keys,
        [
            "fsCreate",
            "fsDelete",
            "fsRead",
            "fsWrite",
            "networkUse",
            "processStart",
        ]
    );
    assert_eq!(map["fsCreate"].as_object().expect("action entry").len(), 4);
}

#[test]
fn managed_ask_requires_exact_approval_and_missing_backend_stays_unavailable() {
    let ask = action(
        PermissionManagedDecisionV2::Ask,
        PermissionPresetBehaviorV2::PerEffectEvaluation,
        PermissionEnforcementAvailabilityV2::MediatedOnly,
    );
    assert_eq!(
        ask.disposition,
        PermissionDispositionV2::RequiresExactApproval {
            reason: PermissionApprovalReasonV2::ManagedAsk,
        }
    );
    let unavailable = action(
        PermissionManagedDecisionV2::Ask,
        PermissionPresetBehaviorV2::PerEffectEvaluation,
        PermissionEnforcementAvailabilityV2::Unavailable {
            reason: PermissionEnforcementUnavailableReasonV2::CurrentEvidenceUnavailable,
        },
    );
    assert!(matches!(
        unavailable.disposition,
        PermissionDispositionV2::Unavailable { .. }
    ));

    let mut action_map = all_actions(action(
        PermissionManagedDecisionV2::Deny,
        PermissionPresetBehaviorV2::ExactApprovalRequired,
        PermissionEnforcementAvailabilityV2::Native,
    ));
    action_map.fs_read = action(
        PermissionManagedDecisionV2::Ask,
        PermissionPresetBehaviorV2::PerEffectEvaluation,
        PermissionEnforcementAvailabilityV2::MediatedOnly,
    );
    let scopes = PermissionModeScopesV2 {
        filesystem: PermissionFilesystemScopeV2 {
            posture: PermissionFilesystemPostureV2::BoundedRoots,
            rights: vec![PermissionFilesystemRightV2::Read],
        },
        process: PermissionProcessScopeV2::None,
        network: PermissionNetworkStateV2::None,
        source_ingress: PermissionSourceIngressV2::Available,
    };
    let status = not_ready_status(
        PermissionModeV1::AskAlways,
        PermissionModeNotReadyReasonV2::PresetUnavailable,
        PermissionModeLifecycleV2::Current,
        action_map,
        scopes,
    );
    assert_eq!(status.validate(), Ok(()));
}

#[test]
fn per_effect_evaluation_can_be_available_without_claiming_this_invocation_is_approved() {
    let mut status = full_access_allow_status();
    status.selected_mode = PermissionModeV1::RiskBased;
    if let PermissionEffectiveStateV2::Ready {
        mode, action_map, ..
    } = &mut status.effective
    {
        *mode = PermissionModeV1::RiskBased;
        for action in [
            &mut action_map.fs_read,
            &mut action_map.fs_create,
            &mut action_map.fs_write,
            &mut action_map.fs_delete,
            &mut action_map.process_start,
            &mut action_map.network_use,
        ]
        .into_iter()
        {
            action.preset_behavior = PermissionPresetBehaviorV2::PerEffectEvaluation;
        }
    }
    assert_eq!(status.validate(), Ok(()));
}

#[test]
fn managed_deny_remains_denied_when_enforcement_is_unavailable() {
    let projection = action(
        PermissionManagedDecisionV2::Deny,
        PermissionPresetBehaviorV2::PerEffectEvaluation,
        PermissionEnforcementAvailabilityV2::Unavailable {
            reason: PermissionEnforcementUnavailableReasonV2::NativeContainmentUnavailable,
        },
    );
    assert_eq!(
        projection.disposition,
        PermissionDispositionV2::Denied {
            reason: PermissionDeniedReasonV2::ManagedDeny,
        }
    );
    let action_map = all_actions(projection);
    let scopes = PermissionModeScopesV2 {
        filesystem: PermissionFilesystemScopeV2 {
            posture: PermissionFilesystemPostureV2::None,
            rights: Vec::new(),
        },
        process: PermissionProcessScopeV2::None,
        network: PermissionNetworkStateV2::Unavailable,
        source_ingress: PermissionSourceIngressV2::Unavailable {
            reason: PermissionSourceIngressUnavailableReasonV2::CurrentEvidenceUnavailable,
        },
    };
    let status = not_ready_status(
        PermissionModeV1::RiskBased,
        PermissionModeNotReadyReasonV2::NativeContainmentUnavailable,
        PermissionModeLifecycleV2::Current,
        action_map,
        scopes,
    );
    assert_eq!(status.validate(), Ok(()));
}

#[test]
fn none_and_unavailable_network_are_distinct_states() {
    let denied = full_access_all_deny_status();
    assert_eq!(denied.network_state, PermissionNetworkStateV2::None);
    assert_eq!(denied.validate(), Ok(()));

    let mut unavailable_map = all_actions(action(
        PermissionManagedDecisionV2::Deny,
        PermissionPresetBehaviorV2::PerEffectEvaluation,
        PermissionEnforcementAvailabilityV2::Native,
    ));
    unavailable_map.network_use = action(
        PermissionManagedDecisionV2::Allow,
        PermissionPresetBehaviorV2::PerEffectEvaluation,
        PermissionEnforcementAvailabilityV2::Unavailable {
            reason: PermissionEnforcementUnavailableReasonV2::NativeContainmentUnavailable,
        },
    );
    let scopes = PermissionModeScopesV2 {
        filesystem: PermissionFilesystemScopeV2 {
            posture: PermissionFilesystemPostureV2::None,
            rights: Vec::new(),
        },
        process: PermissionProcessScopeV2::None,
        network: PermissionNetworkStateV2::Unavailable,
        source_ingress: PermissionSourceIngressV2::Unavailable {
            reason: PermissionSourceIngressUnavailableReasonV2::CurrentEvidenceUnavailable,
        },
    };
    let status = not_ready_status(
        PermissionModeV1::RiskBased,
        PermissionModeNotReadyReasonV2::NativeContainmentUnavailable,
        PermissionModeLifecycleV2::Current,
        unavailable_map,
        scopes,
    );
    assert_eq!(status.validate(), Ok(()));

    assert_eq!(
        serde_json::to_value(PermissionNetworkStateV2::None).expect("none network"),
        serde_json::json!("none")
    );
    assert_eq!(
        serde_json::to_value(PermissionNetworkStateV2::Unavailable).expect("unavailable network"),
        serde_json::json!("unavailable")
    );
}

#[test]
fn unavailable_source_provenance_does_not_rewrite_generic_fs_read_decision() {
    let mut action_map = all_actions(action(
        PermissionManagedDecisionV2::Deny,
        PermissionPresetBehaviorV2::PerEffectEvaluation,
        PermissionEnforcementAvailabilityV2::Native,
    ));
    action_map.fs_read = action(
        PermissionManagedDecisionV2::Allow,
        PermissionPresetBehaviorV2::PerEffectEvaluation,
        PermissionEnforcementAvailabilityV2::MediatedOnly,
    );
    let scopes = PermissionModeScopesV2 {
        filesystem: PermissionFilesystemScopeV2 {
            posture: PermissionFilesystemPostureV2::BoundedRoots,
            rights: vec![PermissionFilesystemRightV2::Read],
        },
        process: PermissionProcessScopeV2::None,
        network: PermissionNetworkStateV2::None,
        source_ingress: PermissionSourceIngressV2::Unavailable {
            reason: PermissionSourceIngressUnavailableReasonV2::ProvenanceUnavailable,
        },
    };
    let status = not_ready_status(
        PermissionModeV1::RiskBased,
        PermissionModeNotReadyReasonV2::SourceProvenanceUnavailable,
        PermissionModeLifecycleV2::Current,
        action_map,
        scopes,
    );
    assert_eq!(status.validate(), Ok(()));
    let PermissionEffectiveStateV2::NotReady { action_map, .. } = status.effective else {
        panic!("missing source provenance must retain partial NotReady state");
    };
    assert_eq!(
        action_map.fs_read.managed_decision,
        PermissionManagedDecisionV2::Allow
    );
    assert_eq!(
        action_map.fs_read.disposition,
        PermissionDispositionV2::Available
    );
}

#[test]
fn each_actionable_filesystem_class_requires_its_canonical_scope_right() {
    for right in [
        PermissionFilesystemRightV2::Read,
        PermissionFilesystemRightV2::Create,
        PermissionFilesystemRightV2::Write,
        PermissionFilesystemRightV2::Delete,
    ] {
        let mut status = full_access_allow_status();
        if let PermissionEffectiveStateV2::Ready { scopes, .. } = &mut status.effective {
            scopes
                .filesystem
                .rights
                .retain(|candidate| *candidate != right);
        }
        assert!(
            status.validate().is_err(),
            "accepted missing {right:?} right"
        );
    }
}

#[test]
fn filesystem_rights_must_be_sorted_unique_and_empty_for_none_posture() {
    for rights in [
        vec![
            PermissionFilesystemRightV2::Create,
            PermissionFilesystemRightV2::Read,
            PermissionFilesystemRightV2::Write,
            PermissionFilesystemRightV2::Delete,
        ],
        vec![
            PermissionFilesystemRightV2::Read,
            PermissionFilesystemRightV2::Read,
            PermissionFilesystemRightV2::Write,
            PermissionFilesystemRightV2::Delete,
        ],
    ] {
        let mut status = full_access_allow_status();
        if let PermissionEffectiveStateV2::Ready { scopes, .. } = &mut status.effective {
            scopes.filesystem.rights = rights;
        }
        assert!(status.validate().is_err());
    }

    let mut none_with_right = full_access_all_deny_status();
    if let PermissionEffectiveStateV2::Ready { scopes, .. } = &mut none_with_right.effective {
        scopes.filesystem.rights = vec![PermissionFilesystemRightV2::Read];
    }
    assert!(none_with_right.validate().is_err());
}
