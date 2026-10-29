#[path = "tests_policy.rs"]
mod policy;

use crate::permission_modes::closed_coverage_test_support as support;

use crate::permission_modes::{FilesystemPermission, ManagedPolicyCoverage};
use crate::project_trust::{ManagedEffectClass, ManagedEffectDecision};
use runne_domain::id::IntegrityDigest;

use support::{broad_scope, decisions, snapshot};

#[test]
fn fixed_six_classes_retain_allow_ask_deny_in_canonical_order() {
    for class in ManagedEffectClass::ALL {
        for decision in [
            ManagedEffectDecision::Allow,
            ManagedEffectDecision::Ask,
            ManagedEffectDecision::Deny,
        ] {
            let mut rules = decisions(ManagedEffectDecision::Allow);
            rules[class.tag() as usize - 1] = decision;
            let coverage = ManagedPolicyCoverage::from_closed_snapshot(
                support::project(),
                &snapshot(rules, 9),
            )
            .unwrap();
            let ManagedPolicyCoverage::Closed(evidence) = coverage else {
                panic!("factory must create closed evidence");
            };
            assert_eq!(evidence.disposition(class), decision);
        }
    }
}

#[test]
fn snapshot_identity_recomputes_and_binds_project_status_epoch_revision_and_rules() {
    let project = support::project();
    let rules = decisions(ManagedEffectDecision::Allow);
    let base = ManagedPolicyCoverage::from_closed_snapshot(project, &snapshot(rules, 9))
        .unwrap()
        .policy_digest();
    assert_ne!(base, IntegrityDigest::from_bytes([0; 32]));
    for changed in [
        ManagedPolicyCoverage::from_closed_snapshot(support::other_project(), &snapshot(rules, 9))
            .unwrap()
            .policy_digest(),
        ManagedPolicyCoverage::from_closed_snapshot(project, &snapshot(rules, 10))
            .unwrap()
            .policy_digest(),
        ManagedPolicyCoverage::from_closed_snapshot(
            project,
            &snapshot([ManagedEffectDecision::Ask; 6], 9),
        )
        .unwrap()
        .policy_digest(),
    ] {
        assert_ne!(base, changed);
    }
}

#[test]
fn closed_digest_uses_composite_v2_and_binds_network_and_entire_scope() {
    let decisions = decisions(ManagedEffectDecision::Allow);
    let none = broad_scope(crate::permission_modes::NetworkScope::None, decisions);
    let broad = broad_scope(
        crate::permission_modes::NetworkScope::BroadSameUser,
        decisions,
    );
    assert_ne!(none.digest().unwrap(), broad.digest().unwrap());
    let mut changed = none.clone();
    changed.permission_scope.workspace_id = support::workspace(2);
    assert_ne!(none.digest().unwrap(), changed.digest().unwrap());
    changed = none.clone();
    changed.protected_control_plane_policy_digest = IntegrityDigest::from_bytes([90; 32]);
    assert_ne!(none.digest().unwrap(), changed.digest().unwrap());

    let child = support::bounded_scope([FilesystemPermission::Read], decisions);
    assert!(child.is_attenuated_from(&broad));
    assert_ne!(child.digest().unwrap(), broad.digest().unwrap());
}

#[test]
fn legacy_unrestricted_composite_digest_keeps_the_v1_golden_encoding() {
    let mut scope = broad_scope(
        crate::permission_modes::NetworkScope::BroadSameUser,
        decisions(ManagedEffectDecision::Allow),
    );
    scope.managed_policy = ManagedPolicyCoverage::Unrestricted {
        policy_digest: IntegrityDigest::from_bytes([42; 32]),
    };
    scope.budget.max_operations = Some(10);
    assert_eq!(
        scope.digest().unwrap().as_bytes(),
        &[
            0x51, 0x88, 0x22, 0x3d, 0xdd, 0xfa, 0xbf, 0x91, 0x5b, 0x31, 0xff, 0x8e, 0x98, 0x33,
            0x42, 0xbb, 0x3a, 0x2e, 0x64, 0x02, 0x1f, 0x69, 0x91, 0x4c, 0xad, 0xb0, 0x9b, 0x95,
            0x3f, 0x93, 0x0f, 0x1b,
        ]
    );
}

#[test]
fn unsupported_snapshot_shapes_fail_closed() {
    let mut invalid = snapshot(decisions(ManagedEffectDecision::Allow), 9);
    invalid.policy.version = 99;
    assert!(ManagedPolicyCoverage::from_closed_snapshot(support::project(), &invalid).is_none());
    assert!(
        ManagedPolicyCoverage::from_closed_snapshot(
            support::zero_project(),
            &snapshot(decisions(ManagedEffectDecision::Allow), 9),
        )
        .is_none()
    );
}

#[test]
fn closed_scope_requires_process_policy_and_network_rule_only_when_network_is_provided() {
    let mut rules = decisions(ManagedEffectDecision::Allow);
    rules[ManagedEffectClass::ProcessStart.tag() as usize - 1] = ManagedEffectDecision::Deny;
    let denied_process = broad_scope(crate::permission_modes::NetworkScope::None, rules);
    assert!(
        !denied_process
            .managed_policy
            .supports_closed_scope(&denied_process)
    );

    let mut rules = decisions(ManagedEffectDecision::Allow);
    rules[ManagedEffectClass::NetworkUse.tag() as usize - 1] = ManagedEffectDecision::Deny;
    let network_none = broad_scope(crate::permission_modes::NetworkScope::None, rules);
    assert!(
        network_none
            .managed_policy
            .supports_closed_scope(&network_none)
    );
    let network_broad = broad_scope(crate::permission_modes::NetworkScope::BroadSameUser, rules);
    assert!(
        !network_broad
            .managed_policy
            .supports_closed_scope(&network_broad)
    );
}

#[path = "tests_workspace_process.rs"]
mod workspace_process;
