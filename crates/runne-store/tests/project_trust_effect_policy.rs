#[path = "project_trust_effect_policy/support.rs"]
mod support;

use runne_application::project_trust::{
    ManagedEffectDecision as D, ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus,
};
use support::{set_fixture_rules, trusted_store};

#[test]
fn effect_snapshot_is_fenced_with_trust_and_ordinary_commits_preserve_rules() {
    let root = tempfile::tempdir().unwrap();
    let (canonical, first, project_bytes) = trusted_store(root.path(), "effect.sqlite");
    set_fixture_rules(&canonical, [1, 2, 0, 0, 1, 2]);
    let second = runne_store::ProjectTrustStore::open(&canonical, [0x4a; 16]).unwrap();
    let project = ProjectTrustProjectId::from_bytes(project_bytes);
    let lease = first.acquire_effect_lease(project).unwrap();
    let snapshot = lease.snapshot().unwrap();
    assert_eq!(snapshot.record, lease.record());
    assert_eq!(snapshot.policy.version, 1);
    assert_eq!(
        snapshot.policy.decisions(),
        [D::Ask, D::Deny, D::Allow, D::Allow, D::Ask, D::Deny]
    );
    assert!(
        second
            .commit(
                project,
                ProjectTrustStatus::Untrusted,
                0,
                snapshot.record.token()
            )
            .is_err()
    );
    drop(lease);

    second
        .commit(
            project,
            ProjectTrustStatus::Trusted,
            0,
            snapshot.record.token(),
        )
        .unwrap();
    let current = second
        .acquire_effect_lease(project)
        .unwrap()
        .snapshot()
        .unwrap();
    assert_eq!(current.policy, snapshot.policy);
    assert_eq!(current.record.revision, snapshot.record.revision + 1);

    let mut control = second.acquire_control_lease(project).unwrap();
    let revoked = control.decide(false, current.record.token()).unwrap();
    drop(control);
    let after_control = second
        .acquire_effect_lease(project)
        .unwrap()
        .snapshot()
        .unwrap();
    assert_eq!(after_control.record, revoked);
    assert_eq!(after_control.policy, snapshot.policy);
}

#[test]
fn control_first_trust_decision_creates_default_policy_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let canonical = support::canonical_path(root.path(), "control-first.sqlite");
    let store = runne_store::ProjectTrustStore::open(&canonical, [0x4a; 16]).unwrap();
    let project = ProjectTrustProjectId::from_bytes([0x71; 16]);
    let mut control = store.acquire_control_lease(project).unwrap();
    let initial = control.record();
    let trusted = control.decide(true, initial.token()).unwrap();
    drop(control);

    let lease = store.acquire_effect_lease(project).unwrap();
    let snapshot = lease.snapshot().unwrap();
    assert_eq!(snapshot.record, trusted);
    assert!(snapshot.policy.is_all_allow());
}

#[test]
fn malformed_persisted_rule_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let (canonical, store, project_bytes) = trusted_store(root.path(), "malformed.sqlite");
    let raw = rusqlite::Connection::open(format!("{}.project-trust", canonical.display())).unwrap();
    raw.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    raw.execute(
        "UPDATE managed_effect_policies SET fs_read=9 WHERE project_id=?1",
        [&project_bytes[..]],
    )
    .unwrap();

    assert!(
        store
            .acquire_effect_lease(ProjectTrustProjectId::from_bytes(project_bytes))
            .is_err()
    );
}

#[test]
fn unknown_persisted_policy_version_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let (canonical, store, project_bytes) = trusted_store(root.path(), "unknown-policy.sqlite");
    let raw = rusqlite::Connection::open(format!("{}.project-trust", canonical.display())).unwrap();
    raw.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    raw.execute(
        "UPDATE managed_effect_policies SET policy_version=9 WHERE project_id=?1",
        [&project_bytes[..]],
    )
    .unwrap();

    assert!(
        store
            .acquire_effect_lease(ProjectTrustProjectId::from_bytes(project_bytes))
            .is_err()
    );
}

#[test]
fn replaced_sidecar_fails_effect_lease_aba_check() {
    let first_root = tempfile::tempdir().unwrap();
    let (canonical, first, project) = trusted_store(first_root.path(), "replaced.sqlite");
    let second_root = tempfile::tempdir().unwrap();
    let (second_canonical, second, _) = trusted_store(second_root.path(), "replacement.sqlite");
    drop(second);
    let original = format!("{}.project-trust", canonical.display());
    let displaced = format!("{}.displaced", canonical.display());
    std::fs::rename(&original, &displaced).unwrap();
    std::fs::copy(
        format!("{}.project-trust", second_canonical.display()),
        &original,
    )
    .unwrap();

    assert!(
        first
            .acquire_effect_lease(ProjectTrustProjectId::from_bytes(project))
            .is_err()
    );
}
