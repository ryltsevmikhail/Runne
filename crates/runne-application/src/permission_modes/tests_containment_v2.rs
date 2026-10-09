use crate::permission_modes::closed_coverage_test_support as support;

use crate::permission_modes::{ContainmentStrategy, FilesystemPermission, NetworkScope};
use crate::project_trust::ManagedEffectDecision;
use std::collections::BTreeSet;

fn hex(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn v2_scope_has_new_tagged_golden_while_v1_scope_bytes_remain_stable() {
    let rules = support::decisions(ManagedEffectDecision::Allow);
    let legacy = support::broad_scope(NetworkScope::None, rules);
    let mut current = legacy.clone();
    current.containment = ContainmentStrategy::SameUserCompositeV2;
    current.filesystem.permissions = BTreeSet::from([
        FilesystemPermission::Read,
        FilesystemPermission::Create,
        FilesystemPermission::Write,
    ]);
    let legacy_digest = legacy.digest().unwrap();
    let current_digest = current.digest().unwrap();
    assert_eq!(
        hex(legacy_digest.as_bytes()),
        "e98e896c7d88812449d6acb28a4c2a10bf1102c48afb6d09399686ac0049a442"
    );
    assert_eq!(
        hex(current_digest.as_bytes()),
        "fd9ef7f6a841eed42e9d1559e33bfd5f7e0050082d0ca22883c30d082e19e6e4"
    );
    assert_ne!(legacy_digest, current_digest);

    let mut changed = current.clone();
    changed.network = NetworkScope::BroadSameUser;
    assert_ne!(current_digest, changed.digest().unwrap());
    changed = current.clone();
    changed
        .filesystem
        .permissions
        .insert(FilesystemPermission::Delete);
    assert_ne!(current_digest, changed.digest().unwrap());
}
