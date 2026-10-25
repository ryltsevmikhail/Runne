#[test]
fn all_closed_scope_families_preserve_rights_options_and_unsupported() {
    use super::retained_context::OriginalSemanticProjectionV1;
    let original = base();
    let rights = [
        FilesystemPermission::Read,
        FilesystemPermission::Create,
        FilesystemPermission::Write,
        FilesystemPermission::Delete,
    ];
    let root = FilesystemRoot::new(IntegrityDigest::from_bytes([9; 32]), vec!["é".into()]).unwrap();
    for containment in [
        ContainmentStrategy::WorkspaceBoundV1,
        ContainmentStrategy::SameUserCompositeV1,
        ContainmentStrategy::SameUserCompositeV2,
    ] {
        for posture in [
            FilesystemPosture::None,
            FilesystemPosture::BoundedRoots([root.clone()].into_iter().collect()),
            FilesystemPosture::BroadSameUser,
        ] {
            for mask in 0u8..16 {
                for network in [NetworkScope::None, NetworkScope::BroadSameUser] {
                    for children in [
                        ChildDelegationScope::None,
                        ChildDelegationScope::MaxDepth(0),
                        ChildDelegationScope::MaxDepth(u16::MAX),
                        ChildDelegationScope::Unbounded,
                    ] {
                        for budget in [
                            EffectBudget {
                                max_operations: None,
                                max_bytes: None,
                            },
                            EffectBudget {
                                max_operations: Some(0),
                                max_bytes: Some(u64::MAX),
                            },
                            EffectBudget {
                                max_operations: Some(u64::MAX),
                                max_bytes: Some(0),
                            },
                        ] {
                            let mut scope = original.scope().clone();
                            scope.containment = containment;
                            scope.filesystem.posture = posture.clone();
                            scope.filesystem.permissions = rights
                                .into_iter()
                                .enumerate()
                                .filter_map(|(i, right)| (mask & (1 << i) != 0).then_some(right))
                                .collect();
                            scope.network = network;
                            scope.children = children;
                            scope.budget = budget;
                            scope.lifetime_ms = u64::MAX;
                            if scope.validate().is_err() {
                                continue;
                            }
                            let binding = rebuild(
                                &original,
                                scope,
                                original.closed_rules_snapshot(),
                                PermissionMode::AskAlways,
                                1,
                                [0; 32],
                            );
                            let decoded = roundtrip(&binding);
                            let supported = matches!(posture, FilesystemPosture::BroadSameUser)
                                && children == ChildDelegationScope::Unbounded
                                && (containment == ContainmentStrategy::SameUserCompositeV1
                                    && mask == 15
                                    || containment == ContainmentStrategy::SameUserCompositeV2
                                        && !(mask & 2 != 0 && mask & 4 == 0));
                            assert_eq!(
                                matches!(
                                    decoded.semantic_projection,
                                    OriginalSemanticProjectionV1::SupportedV1(_)
                                ),
                                supported
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn snapshots_decisions_modes_and_independent_original_expiry_roundtrip() {
    let original = base();
    let project = ProjectTrustProjectId::from_bytes(*original.project_id().as_bytes());
    for status in [
        ProjectTrustStatus::Untrusted,
        ProjectTrustStatus::Trusted,
        ProjectTrustStatus::Managed,
    ] {
        for mode in [
            PermissionMode::AskAlways,
            PermissionMode::RiskBased,
            PermissionMode::FullAccess,
        ] {
            for number in 0u32..729 {
                let mut n = number;
                let mut decisions = [ManagedEffectDecision::Allow; 6];
                for decision in &mut decisions {
                    *decision = [
                        ManagedEffectDecision::Allow,
                        ManagedEffectDecision::Ask,
                        ManagedEffectDecision::Deny,
                    ][usize::try_from(n % 3).unwrap()];
                    n /= 3;
                }
                let snapshot = ProjectTrustEffectPolicySnapshot {
                    record: ProjectTrustRecord {
                        status,
                        instance_epoch: u64::MAX,
                        revision: if status == ProjectTrustStatus::Untrusted {
                            0
                        } else {
                            8
                        },
                        managed_deny_mask: 0,
                    },
                    policy: ManagedEffectPolicyV1::new(1, decisions),
                };
                let mut scope = original.scope().clone();
                scope.lifetime_ms = 1;
                scope.managed_policy =
                    ManagedPolicyCoverage::from_closed_snapshot(project, &snapshot).unwrap();
                let binding = rebuild(&original, scope, snapshot, mode, 42, [0; 32]);
                let decoded = roundtrip(&binding);
                assert_eq!(decoded.approval.expires_at_unix_ms, 42);
                assert_eq!(
                    decoded.approval.relevant_policy_digest,
                    IntegrityDigest::from_bytes([0; 32])
                );
            }
        }
    }
}

#[test]
fn maximum_bounded_roots_and_empty_components_fit_losslessly() {
    let original = base();
    let mut scope = original.scope().clone();
    scope.containment = ContainmentStrategy::WorkspaceBoundV1;
    let components = vec!["a".repeat(255); 16]; // 4095 joined bytes.
    scope.filesystem.posture = FilesystemPosture::BoundedRoots(
        (1u8..=64)
            .map(|byte| {
                FilesystemRoot::new(IntegrityDigest::from_bytes([byte; 32]), components.clone())
                    .unwrap()
            })
            .collect(),
    );
    roundtrip(&rebuild(
        &original,
        scope.clone(),
        original.closed_rules_snapshot(),
        PermissionMode::RiskBased,
        1,
        [4; 32],
    ));
    scope.filesystem.posture = FilesystemPosture::BoundedRoots(
        [FilesystemRoot::new(IntegrityDigest::from_bytes([9; 32]), vec![]).unwrap()]
            .into_iter()
            .collect(),
    );
    roundtrip(&rebuild(
        &original,
        scope.clone(),
        original.closed_rules_snapshot(),
        PermissionMode::RiskBased,
        1,
        [4; 32],
    ));
    scope.filesystem.posture = FilesystemPosture::BoundedRoots(
        [
            FilesystemRoot::new(IntegrityDigest::from_bytes([9; 32]), vec!["a".into(); 256])
                .unwrap(),
        ]
        .into_iter()
        .collect(),
    );
    roundtrip(&rebuild(
        &original,
        scope,
        original.closed_rules_snapshot(),
        PermissionMode::RiskBased,
        1,
        [4; 32],
    ));
}
