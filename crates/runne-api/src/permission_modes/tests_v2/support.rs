pub(super) use crate::permission_modes::*;
pub(super) use runne_domain::id::{ApprovalId, CommandId, IntegrityDigest};

pub const ID_BYTES: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];

pub fn command_id() -> CommandId {
    CommandId::from_bytes(ID_BYTES)
}

pub fn action(
    managed_decision: PermissionManagedDecisionV2,
    preset_behavior: PermissionPresetBehaviorV2,
    enforcement_availability: PermissionEnforcementAvailabilityV2,
) -> PermissionActionProjectionV2 {
    let operational = matches!(
        enforcement_availability,
        PermissionEnforcementAvailabilityV2::Native
            | PermissionEnforcementAvailabilityV2::MediatedOnly
    );
    let disposition = match managed_decision {
        PermissionManagedDecisionV2::Deny => PermissionDispositionV2::Denied {
            reason: PermissionDeniedReasonV2::ManagedDeny,
        },
        PermissionManagedDecisionV2::Ask => {
            if operational {
                PermissionDispositionV2::RequiresExactApproval {
                    reason: PermissionApprovalReasonV2::ManagedAsk,
                }
            } else {
                PermissionDispositionV2::Unavailable {
                    reason: PermissionDispositionUnavailableReasonV2::EnforcementUnavailable,
                }
            }
        }
        PermissionManagedDecisionV2::Allow if !operational => {
            PermissionDispositionV2::Unavailable {
                reason: PermissionDispositionUnavailableReasonV2::EnforcementUnavailable,
            }
        }
        PermissionManagedDecisionV2::Allow
            if preset_behavior == PermissionPresetBehaviorV2::ExactApprovalRequired =>
        {
            PermissionDispositionV2::RequiresExactApproval {
                reason: PermissionApprovalReasonV2::Preset,
            }
        }
        PermissionManagedDecisionV2::Allow => PermissionDispositionV2::Available,
    };
    PermissionActionProjectionV2 {
        managed_decision,
        preset_behavior,
        enforcement_availability,
        disposition,
    }
}

pub fn all_actions(action: PermissionActionProjectionV2) -> PermissionActionMapV2 {
    PermissionActionMapV2 {
        fs_read: action,
        fs_create: action,
        fs_write: action,
        fs_delete: action,
        process_start: action,
        network_use: action,
    }
}

pub fn full_access_allow_status() -> PermissionModeStatusV2 {
    let action = action(
        PermissionManagedDecisionV2::Allow,
        PermissionPresetBehaviorV2::NoPresetPrompt,
        PermissionEnforcementAvailabilityV2::Native,
    );
    let action_map = all_actions(action);
    let containment = PermissionContainmentV2::SameUserCompositeV2;
    let scopes = PermissionModeScopesV2 {
        filesystem: PermissionFilesystemScopeV2 {
            posture: PermissionFilesystemPostureV2::BroadSameUser,
            rights: vec![
                PermissionFilesystemRightV2::Read,
                PermissionFilesystemRightV2::Create,
                PermissionFilesystemRightV2::Write,
                PermissionFilesystemRightV2::Delete,
            ],
        },
        process: PermissionProcessScopeV2::ArbitraryInsideContainment,
        network: PermissionNetworkStateV2::BroadSameUser,
        source_ingress: PermissionSourceIngressV2::Available,
    };
    ready_status(action_map, scopes, containment)
}

pub fn full_access_all_deny_status() -> PermissionModeStatusV2 {
    let action_map = all_actions(action(
        PermissionManagedDecisionV2::Deny,
        PermissionPresetBehaviorV2::NoPresetPrompt,
        PermissionEnforcementAvailabilityV2::Native,
    ));
    let scopes = PermissionModeScopesV2 {
        filesystem: PermissionFilesystemScopeV2 {
            posture: PermissionFilesystemPostureV2::None,
            rights: Vec::new(),
        },
        process: PermissionProcessScopeV2::None,
        network: PermissionNetworkStateV2::None,
        source_ingress: PermissionSourceIngressV2::Unavailable {
            reason: PermissionSourceIngressUnavailableReasonV2::CurrentEvidenceUnavailable,
        },
    };
    ready_status(
        action_map,
        scopes,
        PermissionContainmentV2::SameUserCompositeV1,
    )
}

pub fn ready_status(
    action_map: PermissionActionMapV2,
    scopes: PermissionModeScopesV2,
    containment: PermissionContainmentV2,
) -> PermissionModeStatusV2 {
    PermissionModeStatusV2 {
        selected_mode: PermissionModeV1::FullAccess,
        effective: PermissionEffectiveStateV2::Ready {
            mode: PermissionModeV1::FullAccess,
            preset_version: PermissionPresetVersionV1::V1,
            scope_digest: IntegrityDigest::from_bytes([9; 32]),
            containment,
            action_map,
            scopes: scopes.clone(),
        },
        authorization_revision: 8,
        preset_version: PermissionPresetVersionV1::V1,
        managed_policy_version: 3,
        pending_approval_ids: Vec::new(),
        containment: Some(containment),
        network_state: scopes.network,
        expires_at_unix_ms: Some(1_700_000_000_000),
        observation_generation: 4,
        lifecycle: PermissionModeLifecycleV2::Current,
    }
}

pub fn not_ready_status(
    selected_mode: PermissionModeV1,
    reason: PermissionModeNotReadyReasonV2,
    lifecycle: PermissionModeLifecycleV2,
    action_map: PermissionActionMapV2,
    scopes: PermissionModeScopesV2,
) -> PermissionModeStatusV2 {
    PermissionModeStatusV2 {
        selected_mode,
        effective: PermissionEffectiveStateV2::NotReady {
            reason,
            action_map,
            scopes: scopes.clone(),
        },
        authorization_revision: 8,
        preset_version: PermissionPresetVersionV1::V1,
        managed_policy_version: 3,
        pending_approval_ids: Vec::new(),
        containment: Some(PermissionContainmentV2::SameUserCompositeV1),
        network_state: scopes.network,
        expires_at_unix_ms: None,
        observation_generation: 4,
        lifecycle,
    }
}

pub fn v1_status() -> PermissionModeStatusV1 {
    PermissionModeStatusV1 {
        selected_mode: PermissionModeV1::RiskBased,
        effective: PermissionEffectiveStateV1::NotReady {
            reason: PermissionModeNotReadyReasonV1::PresetUnavailable,
        },
        authorization_revision: 8,
        preset_version: PermissionPresetVersionV1::V1,
        managed_policy_version: 3,
        pending_approval_ids: vec![ApprovalId::from_bytes(ID_BYTES)],
        containment: None,
        network_state: PermissionNetworkStateV1::Unavailable,
        expires_at_unix_ms: None,
    }
}

pub fn v1_history() -> PermissionModeHistoryV1 {
    PermissionModeHistoryV1 {
        selected_mode: PermissionModeV1::RiskBased,
        effective: PermissionEffectiveStateV1::NotReady {
            reason: PermissionModeNotReadyReasonV1::PresetUnavailable,
        },
        authorization_revision: 8,
        preset_version: PermissionPresetVersionV1::V1,
        managed_policy_version: 3,
        containment: None,
        network_state: PermissionNetworkStateV1::Unavailable,
        expires_at_unix_ms: None,
    }
}

pub fn v1_receipt() -> PermissionModeChangeReceiptV1 {
    PermissionModeChangeReceiptV1 {
        command_id: command_id(),
        idempotency_key: "mode-change-1".to_owned(),
        intent_digest: IntegrityDigest::from_bytes([2; 32]),
        authorization_revision: 8,
        selected_mode: PermissionModeV1::RiskBased,
        history: v1_history(),
    }
}

pub fn v2_receipt(history: PermissionModeHistoryV2) -> PermissionModeChangeReceiptV2 {
    PermissionModeChangeReceiptV2 {
        command_id: command_id(),
        idempotency_key: "mode-change-2".to_owned(),
        intent_digest: IntegrityDigest::from_bytes([3; 32]),
        authorization_revision: history.authorization_revision,
        selected_mode: history.selected_mode,
        history,
    }
}
