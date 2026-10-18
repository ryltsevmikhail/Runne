use crate::permission_modes::closed_coverage_test_support as support;

use crate::permission_modes::{ContainmentStrategy, FilesystemPermission, NetworkScope};
use crate::project_trust::{ManagedEffectClass, ManagedEffectDecision};
use std::collections::BTreeSet;

fn v2_scope(
    network: NetworkScope,
    rights: impl IntoIterator<Item = FilesystemPermission>,
    rules: [ManagedEffectDecision; 6],
) -> crate::permission_modes::CompositeEffectScope {
    let mut scope = support::broad_scope(network, rules);
    scope.containment = ContainmentStrategy::SameUserCompositeV2;
    scope.filesystem.permissions = rights.into_iter().collect::<BTreeSet<_>>();
    scope
}

#[test]
fn v2_shape_is_independent_of_every_allow_ask_deny_decision() {
    let rights = [
        FilesystemPermission::Read,
        FilesystemPermission::Create,
        FilesystemPermission::Write,
    ];
    for class in ManagedEffectClass::ALL {
        for decision in [
            ManagedEffectDecision::Allow,
            ManagedEffectDecision::Ask,
            ManagedEffectDecision::Deny,
        ] {
            let mut rules = support::decisions(ManagedEffectDecision::Allow);
            rules[class.tag() as usize - 1] = decision;
            let scope = v2_scope(NetworkScope::BroadSameUser, rights, rules);
            assert!(scope.validate().is_ok(), "{class:?} {decision:?}");
            assert!(scope.managed_policy.supports_scope_shape(&scope));
            assert!(scope.managed_policy.supports_closed_scope(&scope));
        }
    }
}

#[test]
fn v2_minimum_uses_only_provided_fs_rights_and_requested_network() {
    let mut rules = support::decisions(ManagedEffectDecision::Allow);
    rules[ManagedEffectClass::FsDelete.tag() as usize - 1] = ManagedEffectDecision::Deny;
    rules[ManagedEffectClass::NetworkUse.tag() as usize - 1] = ManagedEffectDecision::Deny;
    let no_network = v2_scope(
        NetworkScope::None,
        [
            FilesystemPermission::Read,
            FilesystemPermission::Create,
            FilesystemPermission::Write,
        ],
        rules,
    );
    assert_eq!(
        no_network
            .managed_policy
            .scope_minimum_disposition(&no_network),
        Some(ManagedEffectDecision::Allow)
    );

    let with_delete = v2_scope(
        NetworkScope::None,
        [
            FilesystemPermission::Read,
            FilesystemPermission::Create,
            FilesystemPermission::Write,
            FilesystemPermission::Delete,
        ],
        rules,
    );
    assert_eq!(
        with_delete
            .managed_policy
            .scope_minimum_disposition(&with_delete),
        Some(ManagedEffectDecision::Deny)
    );

    let with_network = v2_scope(
        NetworkScope::BroadSameUser,
        [FilesystemPermission::Read],
        rules,
    );
    assert_eq!(
        with_network
            .managed_policy
            .scope_minimum_disposition(&with_network),
        Some(ManagedEffectDecision::Deny)
    );
}

#[test]
fn v2_content_create_requires_the_write_policy_class() {
    let mut rules = support::decisions(ManagedEffectDecision::Allow);
    rules[ManagedEffectClass::FsWrite.tag() as usize - 1] = ManagedEffectDecision::Deny;
    let scope = v2_scope(NetworkScope::None, [FilesystemPermission::Create], rules);
    assert!(scope.managed_policy.supports_scope_shape(&scope));
    assert_eq!(
        scope.managed_policy.scope_minimum_disposition(&scope),
        Some(ManagedEffectDecision::Deny)
    );
}
