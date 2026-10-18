use super::*;

#[test]
fn current_projection_released_gate_runs_native_probe_and_maps_result() {
    let selected = selection(PermissionMode::FullAccess, 4, None);
    let scope = local_command_scope(
        &selected,
        selected.scope.clone(),
        ProjectTrustProjectId::from_bytes([9; 16]),
        &trust_snapshot(8),
        digest(46),
    )
    .unwrap();
    let observed = observe_scope(&selected, &scope, &CountingAdmission::new(), 100).unwrap();
    let expected_effective = observed.effective.clone();
    let called = AtomicUsize::new(0);
    let projection = current_projection(
        ProjectionMetadata {
            selection: selected.clone(),
            managed_policy_version: 8,
        },
        || {
            called.fetch_add(1, Ordering::SeqCst);
            Ok(observed)
        },
    );
    assert_eq!(called.load(Ordering::SeqCst), 1);
    assert_eq!(projection.effective, expected_effective);
    assert!(matches!(projection.effective, EffectiveModeState::Ready(_)));
    assert_eq!(
        projection.containment,
        Some(ContainmentStrategy::SameUserCompositeV1)
    );
    assert_eq!(projection.network_state, NetworkState::BroadSameUser);
    assert_eq!(projection.authorization_revision, 4);

    let failed = current_projection(
        ProjectionMetadata {
            selection: selected,
            managed_policy_version: 8,
        },
        || Err(NotReadyReason::PresetUnavailable),
    );
    assert_eq!(
        failed.effective,
        EffectiveModeState::NotReady(NotReadyReason::PresetUnavailable)
    );
    assert_eq!(failed.containment, None);
    assert_eq!(failed.network_state, NetworkState::Unavailable);
    assert_eq!(failed.authorization_revision, 4);
}

#[test]
fn direct_core_probe_uses_full_access_network_and_never_admits_an_invocation() {
    let project = ProjectTrustProjectId::from_bytes([9; 16]);
    let trust = trust_snapshot(8);
    let native = CountingAdmission::new();
    for mode in [
        PermissionMode::AskAlways,
        PermissionMode::RiskBased,
        PermissionMode::FullAccess,
    ] {
        let selected = selection(mode, 2, None);
        let scope = local_command_scope(
            &selected,
            selected.scope.clone(),
            project,
            &trust,
            digest(43),
        )
        .unwrap();
        let full_access = mode == PermissionMode::FullAccess;
        assert_eq!(
            scope.network,
            if full_access {
                NetworkScope::BroadSameUser
            } else {
                NetworkScope::None
            }
        );
        let observed = observe_scope(&selected, &scope, &native, 100).unwrap();
        assert!(matches!(observed.effective, EffectiveModeState::Ready(_)));
        assert_eq!(
            observed.network_state,
            if full_access {
                NetworkState::BroadSameUser
            } else {
                NetworkState::Unavailable
            }
        );
    }
    assert_eq!(native.readiness.load(Ordering::SeqCst), 3);
    assert_eq!(native.invocation.load(Ordering::SeqCst), 0);
}

#[test]
fn unavailable_native_readiness_is_reported_without_invocation_admission() {
    let selected = selection(PermissionMode::RiskBased, 2, None);
    let trust = trust_snapshot(8);
    let scope = local_command_scope(
        &selected,
        selected.scope.clone(),
        ProjectTrustProjectId::from_bytes([9; 16]),
        &trust,
        digest(45),
    )
    .unwrap();
    let native = UnavailableAdmission(AtomicUsize::new(0));
    assert!(matches!(
        observe_scope(&selected, &scope, &native, 100),
        Err(NotReadyReason::NativeContainment)
    ));
    assert_eq!(native.0.load(Ordering::SeqCst), 1);
}

#[test]
fn expired_selection_is_rejected_before_native_readiness_admission() {
    let selected = selection(PermissionMode::RiskBased, 2, Some(99));
    let trust = trust_snapshot(8);
    let scope = local_command_scope(
        &selected,
        selected.scope.clone(),
        ProjectTrustProjectId::from_bytes([9; 16]),
        &trust,
        digest(44),
    )
    .unwrap();
    let native = CountingAdmission::new();
    assert!(matches!(
        observe_scope(&selected, &scope, &native, 100),
        Err(NotReadyReason::NativeContainment)
    ));
    assert_eq!(native.readiness.load(Ordering::SeqCst), 0);
}

#[test]
#[cfg(target_os = "linux")]
fn candidate_projection_rejects_revision_and_managed_policy_drift() {
    let selected = selection(PermissionMode::AskAlways, 3, None);
    let managed = managed_identity(selected.clone(), 8, digest(51));
    let ManagedIdentityMetadata::ClosedRulesV2(managed_rules) = &managed.identity else {
        unreachable!();
    };
    let candidate = ModeSelection {
        selected_mode: PermissionMode::FullAccess,
        authorization_revision: 4,
        ..selected.clone()
    };
    let target = ProjectionTarget::Candidate {
        selection: candidate.clone(),
        expected_revision: 3,
        managed_policy_version: 8,
        managed_policy_digest: digest(51),
    };
    assert_eq!(
        crate::application::permission_projection_runtime::selected_target(
            &target,
            &managed,
            managed_rules,
        ),
        Ok(candidate.clone())
    );

    let stale_revision = ProjectionTarget::Candidate {
        selection: candidate.clone(),
        expected_revision: 2,
        managed_policy_version: 8,
        managed_policy_digest: digest(51),
    };
    assert_eq!(
        crate::application::permission_projection_runtime::selected_target(
            &stale_revision,
            &managed,
            managed_rules,
        ),
        Err(NotReadyReason::NativeContainment)
    );
    let stale_policy = ProjectionTarget::Candidate {
        selection: candidate.clone(),
        expected_revision: 3,
        managed_policy_version: 9,
        managed_policy_digest: digest(51),
    };
    assert_eq!(
        crate::application::permission_projection_runtime::selected_target(
            &stale_policy,
            &managed,
            managed_rules,
        ),
        Err(NotReadyReason::NativeContainment)
    );
    let changed_digest = ProjectionTarget::Candidate {
        selection: candidate,
        expected_revision: 3,
        managed_policy_version: 8,
        managed_policy_digest: digest(52),
    };
    assert_eq!(
        crate::application::permission_projection_runtime::selected_target(
            &changed_digest,
            &managed,
            managed_rules,
        ),
        Err(NotReadyReason::NativeContainment)
    );
}

#[test]
#[cfg(target_os = "linux")]
fn current_projection_accepts_missing_selection_with_stale_snapshot_policy_version() {
    // No durable row exists: the status snapshot reports managed_policy_version 0
    // while the identity loader pairs the same missing selection with the live
    // closed-rules revision; the stale snapshot constant must not fence the
    // projection (regression: bare `permissions status` was pinned notReady).
    let missing = selection(PermissionMode::AskAlways, 0, None);
    let managed = managed_identity(missing.clone(), 1, digest(61));
    let ManagedIdentityMetadata::ClosedRulesV2(managed_rules) = &managed.identity else {
        unreachable!();
    };
    let target = ProjectionTarget::Current {
        selection: missing.clone(),
        managed_policy_version: 0,
    };
    assert_eq!(
        crate::application::permission_projection_runtime::selected_target(
            &target,
            &managed,
            managed_rules,
        ),
        Ok(missing)
    );
}

#[test]
#[cfg(target_os = "linux")]
fn current_projection_still_rejects_committed_revision_with_stale_policy_version() {
    // A committed row always persists revision >= 1; for those the strict
    // managed-policy version fence must keep rejecting drift.
    let committed = selection(PermissionMode::AskAlways, 2, None);
    let managed = managed_identity(committed.clone(), 7, digest(62));
    let ManagedIdentityMetadata::ClosedRulesV2(managed_rules) = &managed.identity else {
        unreachable!();
    };
    let target = ProjectionTarget::Current {
        selection: committed,
        managed_policy_version: 6,
    };
    assert_eq!(
        crate::application::permission_projection_runtime::selected_target(
            &target,
            &managed,
            managed_rules,
        ),
        Err(NotReadyReason::NativeContainment)
    );
}
