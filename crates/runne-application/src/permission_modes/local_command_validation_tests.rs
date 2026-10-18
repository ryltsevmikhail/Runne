use super::*;

#[test]
fn rejects_each_duplicated_identity_and_supplied_digest_mismatch() {
    let cases: [fn(&mut LocalCommandPermissionBindingInputV1); 8] = [
        |input| input.selection.scope.workspace_id = WorkspaceId::from_bytes([8; 16]),
        |input| {
            input.assignment.taskrun_id =
                TaskRunId::from_str("018f2e3a-7000-7000-8000-000000000004").unwrap()
        },
        |input| {
            input.assignment.attempt_id =
                AttemptId::from_str("018f2e3a-7000-7000-8000-000000000005").unwrap()
        },
        |input| {
            input.invocation_id =
                InvocationId::from_str("018f2e3a-7000-7000-8000-000000000006").unwrap()
        },
        |input| input.approval.principal_id = runne_api::ApiPrincipalId::new("user:other").unwrap(),
        |input| input.command_intent_digest = digest(99),
        |input| input.closed_rules_digest = digest(99),
        |input| input.approval.composite_scope_digest = CompositeScopeDigest::from_bytes([99; 32]),
    ];
    for mutate in cases {
        let mut input = sample_input();
        mutate(&mut input);
        assert!(LocalCommandPermissionBindingV1::checked(input).is_err());
    }
}

#[test]
fn reconstructs_full_closed_snapshot_and_rejects_scope_mismatch() {
    let mut changed = sample_input();
    changed.closed_rules_snapshot.policy = changed
        .closed_rules_snapshot
        .policy
        .with_decision(ManagedEffectClass::FsDelete, ManagedEffectDecision::Deny);
    changed.closed_rules_digest = IntegrityDigest::from_bytes(
        managed_effect_policy_digest_v2(
            crate::project_trust::ProjectTrustProjectId::from_bytes(*changed.project_id.as_bytes()),
            &changed.closed_rules_snapshot,
        )
        .unwrap(),
    );
    assert!(matches!(
        LocalCommandPermissionBindingV1::checked(changed),
        Err(LocalCommandPermissionBindingError::InvalidManagedSnapshot)
    ));
}

#[test]
fn enforces_root_and_native_environment_boundaries() {
    let mut too_many_roots = sample_input();
    let mut roots = BTreeSet::new();
    for value in 0..65_u8 {
        roots.insert(FilesystemRoot::new(digest(value.saturating_add(1)), Vec::new()).unwrap());
    }
    too_many_roots.scope.filesystem.posture = FilesystemPosture::BoundedRoots(roots);
    assert!(LocalCommandPermissionBindingV1::checked(too_many_roots).is_err());

    let mut long_component = sample_input();
    long_component.scope.filesystem.posture =
        FilesystemPosture::BoundedRoots(BTreeSet::from([FilesystemRoot::new(
            digest(20),
            vec!["x".repeat(256)],
        )
        .unwrap()]));
    assert!(LocalCommandPermissionBindingV1::checked(long_component).is_err());

    let mut long_path = sample_input();
    long_path.scope.filesystem.posture =
        FilesystemPosture::BoundedRoots(BTreeSet::from([FilesystemRoot::new(
            digest(21),
            vec!["x".repeat(255); 17],
        )
        .unwrap()]));
    assert!(LocalCommandPermissionBindingV1::checked(long_path).is_err());

    let mut too_long_env_entry = sample_input();
    too_long_env_entry.command = TaskRunLocalCommand::new(
        too_long_env_entry.command.executable().clone(),
        ".".into(),
        vec!["sh".into()],
        vec![("K".into(), "v".repeat(16 * 1024 - 1))],
    )
    .unwrap();
    too_long_env_entry.command_intent_digest =
        IntegrityDigest::from_bytes(too_long_env_entry.command.intent_digest());
    assert!(LocalCommandPermissionBindingV1::checked(too_long_env_entry).is_err());
}

#[test]
fn rejects_oversized_binding_before_digest_work_and_invalid_limits() {
    let mut oversized = sample_input();
    oversized.assignment.node_id.0 = "n".repeat(1024 * 1024);
    assert!(matches!(
        LocalCommandPermissionBindingV1::checked(oversized),
        Err(LocalCommandPermissionBindingError::BindingTooLarge)
    ));

    assert!(matches!(
        LocalInvocationLimitsV1::checked(65_537, 0, 1),
        Err(LocalInvocationLimitsError::CaptureLimitExceeded)
    ));
    assert!(matches!(
        LocalInvocationLimitsV1::checked(0, 0, 0),
        Err(LocalInvocationLimitsError::RuntimeMustBePositive)
    ));
    let limits = LocalInvocationLimitsV1::checked(0, 65_536, u64::MAX).unwrap();
    assert_eq!(limits.max_runtime().unwrap().as_millis(), u64::MAX as u128);
}
