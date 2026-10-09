use runne_application::project_trust::{ProjectTrustPersistence, ProjectTrustProjectId};
use runne_store::ProjectTrustStore;

use super::support::{AUTHORITY, AdminFixture, canonical, now_ms, session, session_as};

#[test]
fn registration_is_preproject_idempotent_and_singleton() {
    let root = tempfile::tempdir().unwrap();
    let path = canonical(root.path(), "registration.sqlite");
    let store = ProjectTrustStore::open(&path, AUTHORITY).unwrap();
    let binding = session(1, 1, now_ms() + 60_000);
    let fixture = AdminFixture::new(binding.clone());
    let bootstrap = fixture.bootstrap(&binding);
    assert!(
        !store
            .has_explicit_record(ProjectTrustProjectId::from_bytes([0x71; 16]))
            .unwrap()
    );
    assert_eq!(
        fixture
            .with(&binding, |current| store
                .register_admin(current, &bootstrap))
            .unwrap(),
        runne_application::project_trust::admin::ManagedPolicyRoleState::Active { generation: 1 }
    );
    assert_eq!(
        fixture
            .with(&binding, |current| store
                .register_admin(current, &bootstrap))
            .unwrap(),
        runne_application::project_trust::admin::ManagedPolicyRoleState::Active { generation: 1 }
    );

    let foreign = session_as("other-owner", 1, 1, now_ms() + 60_000);
    let other = AdminFixture::new(foreign.clone());
    let other_bootstrap = other.bootstrap(&foreign);
    assert!(matches!(
        other.with(&foreign, |current| store
            .register_admin(current, &other_bootstrap)),
        Err(runne_application::project_trust::admin::AdminError::Conflict)
    ));
}

#[test]
fn revocation_advances_every_explicit_revision_and_preserves_rules() {
    use runne_application::project_trust::{ProjectTrustStatus, TrustToken};

    let root = tempfile::tempdir().unwrap();
    let path = canonical(root.path(), "revoke.sqlite");
    let store = ProjectTrustStore::open(&path, AUTHORITY).unwrap();
    let epoch = store.instance_epoch().unwrap();
    let first = ProjectTrustProjectId::from_bytes([0x71; 16]);
    let second = ProjectTrustProjectId::from_bytes([0x72; 16]);
    store
        .commit(
            first,
            ProjectTrustStatus::Trusted,
            9,
            TrustToken::new(epoch, 0),
        )
        .unwrap();
    store
        .commit(
            second,
            ProjectTrustStatus::Managed,
            21,
            TrustToken::new(epoch, 0),
        )
        .unwrap();
    let binding = session(1, 1, now_ms() + 60_000);
    let fixture = AdminFixture::new(binding.clone());
    let bootstrap = fixture.bootstrap(&binding);
    fixture
        .with(&binding, |current| {
            store.register_admin(current, &bootstrap)
        })
        .unwrap();
    let before = [read_snapshot(&store, first), read_snapshot(&store, second)];
    fixture
        .with(&binding, |current| store.revoke_admin(current))
        .unwrap();
    let after = [read_snapshot(&store, first), read_snapshot(&store, second)];
    for (old, new) in before.into_iter().zip(after) {
        assert_eq!(new.record.revision, old.record.revision + 1);
        assert_eq!(new.record.status, old.record.status);
        assert_eq!(new.record.managed_deny_mask, old.record.managed_deny_mask);
        assert_eq!(new.policy, old.policy);
    }
    let state = fixture
        .with(&binding, |current| store.admin_role_state(current))
        .unwrap();
    assert_eq!(
        state,
        runne_application::project_trust::admin::ManagedPolicyRoleState::Revoked { generation: 2 }
    );
}

fn read_snapshot(
    store: &ProjectTrustStore,
    project: ProjectTrustProjectId,
) -> runne_application::project_trust::ProjectTrustEffectPolicySnapshot {
    let lease = store.acquire_effect_lease(project).unwrap();
    lease.snapshot().unwrap()
}
