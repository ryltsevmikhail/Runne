use super::*;

fn digest_for(input: LocalCommandPermissionBindingInputV1) -> IntegrityDigest {
    LocalCommandPermissionBindingV1::checked(input)
        .expect("checked binding")
        .digest()
}

#[test]
fn binding_digest_has_a_frozen_canonical_golden() {
    let binding = LocalCommandPermissionBindingV1::checked(sample_input()).unwrap();
    assert_eq!(
        hex(binding.digest()),
        "d8417e3ff4ccd76bff0a64086f943a283e557e192fb87334767f810f06f1872a"
    );
    assert_eq!(
        hex(super::super::local_command_digest::local_invocation_limits_digest(binding.limits(),)),
        "eb68be184a36c39e0289c5778216008b6df52c4eebfe3d4d9143e2037f9e7032"
    );
}

#[test]
fn every_ordered_managed_rule_changes_the_full_snapshot_binding_digest() {
    let base = digest_for(sample_input());
    for class in ManagedEffectClass::ALL {
        let mut changed = sample_input();
        changed.closed_rules_snapshot.policy = changed
            .closed_rules_snapshot
            .policy
            .with_decision(class, ManagedEffectDecision::Ask);
        refresh_managed_snapshot(&mut changed);
        assert_ne!(base, digest_for(changed), "{class:?} must be covered");
    }
}

#[test]
fn independent_outer_fields_change_the_binding_digest() {
    let base = digest_for(sample_input());

    let mut changed = sample_input();
    changed.claim_stream_version += 1;
    assert_ne!(base, digest_for(changed));

    let mut changed = sample_input();
    changed.project_version += 1;
    assert_ne!(base, digest_for(changed));

    let mut changed = sample_input();
    changed.workspace_version += 1;
    assert_ne!(base, digest_for(changed));

    let mut changed = sample_input();
    changed.admitted_root_version += 1;
    assert_ne!(base, digest_for(changed));

    let mut changed = sample_input();
    changed.held_root_identity_digest = digest(17);
    assert_ne!(base, digest_for(changed));

    let mut changed = sample_input();
    changed.limits = LocalInvocationLimitsV1::checked(1, 2, 5_001).unwrap();
    assert_ne!(base, digest_for(changed));
}

#[test]
fn command_approval_scope_and_selection_are_included_without_changing_legacy_digests() {
    let original = sample_input();
    let base = digest_for(original.clone());

    let mut changed = original.clone();
    changed.command = TaskRunLocalCommand::new(
        changed.command.executable().clone(),
        changed.command.cwd().to_owned(),
        vec!["sh".into(), "-c".into(), "printf changed".into()],
        changed.command.env().to_vec(),
    )
    .unwrap();
    changed.command_intent_digest = IntegrityDigest::from_bytes(changed.command.intent_digest());
    assert_ne!(base, digest_for(changed));

    let mut changed = original.clone();
    changed.approval.tool_schema_digest = digest(18);
    assert_ne!(base, digest_for(changed));

    let mut changed = original.clone();
    changed.selection.authorization_revision += 1;
    assert_ne!(base, digest_for(changed));

    let mut changed = original;
    changed.scope.protected_control_plane_policy_digest = digest(19);
    changed.approval.composite_scope_digest = changed.scope.digest().unwrap();
    assert_ne!(base, digest_for(changed));
}

fn hex(digest: IntegrityDigest) -> String {
    digest
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
