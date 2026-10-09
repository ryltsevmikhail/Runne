use super::support::*;
use runne_domain::id::ApprovalId;

#[test]
fn stale_and_reconciling_states_are_unavailable_and_revoked_is_denied() {
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

    let unavailable = PermissionEnforcementAvailabilityV2::Native;
    let mut stale_map = all_actions(action(
        PermissionManagedDecisionV2::Allow,
        PermissionPresetBehaviorV2::PerEffectEvaluation,
        unavailable,
    ));
    for projection in [
        &mut stale_map.fs_read,
        &mut stale_map.fs_create,
        &mut stale_map.fs_write,
        &mut stale_map.fs_delete,
        &mut stale_map.process_start,
        &mut stale_map.network_use,
    ] {
        projection.disposition = PermissionDispositionV2::Unavailable {
            reason: PermissionDispositionUnavailableReasonV2::StaleObservation,
        };
    }
    let stale = not_ready_status(
        PermissionModeV1::RiskBased,
        PermissionModeNotReadyReasonV2::StaleObservation,
        PermissionModeLifecycleV2::Stale,
        stale_map,
        scopes.clone(),
    );
    assert_eq!(stale.validate(), Ok(()));

    let mut reconcile_map = all_actions(action(
        PermissionManagedDecisionV2::Allow,
        PermissionPresetBehaviorV2::PerEffectEvaluation,
        unavailable,
    ));
    for projection in [
        &mut reconcile_map.fs_read,
        &mut reconcile_map.fs_create,
        &mut reconcile_map.fs_write,
        &mut reconcile_map.fs_delete,
        &mut reconcile_map.process_start,
        &mut reconcile_map.network_use,
    ] {
        projection.disposition = PermissionDispositionV2::Unavailable {
            reason: PermissionDispositionUnavailableReasonV2::Reconciling,
        };
    }
    let reconciling = not_ready_status(
        PermissionModeV1::RiskBased,
        PermissionModeNotReadyReasonV2::Reconciling,
        PermissionModeLifecycleV2::Reconciling,
        reconcile_map,
        scopes.clone(),
    );
    assert_eq!(reconciling.validate(), Ok(()));

    let revoked_map = all_actions(PermissionActionProjectionV2 {
        managed_decision: PermissionManagedDecisionV2::Allow,
        preset_behavior: PermissionPresetBehaviorV2::PerEffectEvaluation,
        enforcement_availability: unavailable,
        disposition: PermissionDispositionV2::Denied {
            reason: PermissionDeniedReasonV2::Revoked,
        },
    });
    let revoked = not_ready_status(
        PermissionModeV1::RiskBased,
        PermissionModeNotReadyReasonV2::Revoked,
        PermissionModeLifecycleV2::Revoked,
        revoked_map,
        scopes,
    );
    assert_eq!(revoked.validate(), Ok(()));
}

#[test]
fn history_is_an_immutable_capture_without_pending_approval_ids_or_current_authority() {
    let mut status = full_access_allow_status();
    status.pending_approval_ids = vec![ApprovalId::from_bytes(ID_BYTES)];
    status.expires_at_unix_ms = Some(1);
    let history = PermissionModeHistoryV2::capture(&status);

    assert_eq!(
        history.authorization_revision,
        status.authorization_revision
    );
    assert_eq!(
        history.observation_generation,
        status.observation_generation
    );
    assert_eq!(history.lifecycle, PermissionModeLifecycleV2::Current);
    assert_eq!(history.expires_at_unix_ms, Some(1));
    assert_eq!(history.validate(), Ok(()));
    let wire = serde_json::to_value(&history).expect("history JSON");
    assert!(wire.get("pendingApprovalIds").is_none());

    status.authorization_revision = 99;
    status.expires_at_unix_ms = Some(2);
    if let PermissionEffectiveStateV2::Ready { action_map, .. } = &mut status.effective {
        action_map.fs_read.managed_decision = PermissionManagedDecisionV2::Deny;
    }
    assert_eq!(history.authorization_revision, 8);
    assert_eq!(history.expires_at_unix_ms, Some(1));
    assert_eq!(
        history.action_map().fs_read.managed_decision,
        PermissionManagedDecisionV2::Allow
    );
}

#[test]
fn revisions_generation_expiry_and_ready_bindings_are_semantically_checked() {
    let mut status = full_access_allow_status();
    status.authorization_revision = i64::MAX as u64 + 1;
    assert_eq!(
        status.validate(),
        Err(PermissionModeValidationErrorV2::RevisionOutOfRange)
    );

    let mut status = full_access_allow_status();
    status.observation_generation = 0;
    assert_eq!(
        status.validate(),
        Err(PermissionModeValidationErrorV2::ZeroObservationGeneration)
    );

    let mut status = full_access_allow_status();
    status.expires_at_unix_ms = Some(0);
    assert_eq!(
        status.validate(),
        Err(PermissionModeValidationErrorV2::InvalidExpiry)
    );

    let mut status = full_access_allow_status();
    status.network_state = PermissionNetworkStateV2::None;
    assert_eq!(
        status.validate(),
        Err(PermissionModeValidationErrorV2::NetworkMismatch)
    );
}
