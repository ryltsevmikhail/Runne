use std::{thread, time::Duration};

use runne_application::project_trust::ProjectTrustProjectId;
use runne_application::project_trust::admin::{
    ManagedPolicyCommandState, ManagedPolicyCommandV1, verify_managed_policy_consent_v1,
};

use super::support::{
    AcceptConsent, AdminFixture, PROJECT, now_ms, request, rules, session, snapshot, trusted_store,
};

#[test]
fn exact_commit_duplicate_after_rotation_and_revoke_returns_original_receipt() {
    let root = tempfile::tempdir().unwrap();
    let (path, store) = trusted_store(root.path(), "commands.sqlite");
    let original_deadline = now_ms() + 5_000;
    let original_binding = session(1, 1, original_deadline);
    let fixture = AdminFixture::new(original_binding.clone());
    super::support::register(&store, &fixture, &original_binding);
    let original_snapshot = snapshot(&store);
    let command = request(
        &original_binding,
        original_snapshot,
        [0x31; 16],
        "request-1",
        1,
    );
    let pending = match fixture
        .with(&original_binding, |current| {
            store.reserve_admin_command(current, &command)
        })
        .unwrap()
    {
        ManagedPolicyCommandState::Pending(command) => command,
        state => panic!("expected pending command, got {state:?}"),
    };
    let consent = fixture
        .with(&original_binding, |current| {
            verify_managed_policy_consent_v1(current, &pending, b"test-only proof", &AcceptConsent)
        })
        .unwrap();
    let committed = fixture
        .with(&original_binding, |current| {
            store.commit_admin_command(current, &pending, &consent)
        })
        .unwrap();
    let receipt = match committed {
        ManagedPolicyCommandState::Committed(receipt) => receipt,
        state => panic!("expected committed receipt, got {state:?}"),
    };
    assert_eq!(receipt.prior_revision(), original_snapshot.record.revision);
    assert_eq!(receipt.revision(), original_snapshot.record.revision + 1);
    let after_commit = snapshot(&store);
    assert_eq!(after_commit.record.revision, receipt.revision());
    assert_eq!(after_commit.policy, rules());

    while now_ms() <= original_deadline {
        thread::sleep(Duration::from_millis(5));
    }
    let rotated = session(2, 2, now_ms() + 60_000);
    fixture.update(rotated.clone());
    let duplicate = request(&rotated, original_snapshot, [0x31; 16], "request-1", 1);
    let replay = fixture
        .with(&rotated, |current| {
            store.reserve_admin_command(current, &duplicate)
        })
        .unwrap();
    assert_eq!(
        replay,
        ManagedPolicyCommandState::Committed(receipt.clone())
    );
    let repeated_commit = fixture
        .with(&rotated, |current| {
            store.commit_admin_command(current, &pending, &consent)
        })
        .unwrap();
    assert_eq!(
        repeated_commit,
        ManagedPolicyCommandState::Committed(receipt.clone())
    );

    fixture
        .with(&rotated, |current| store.revoke_admin(current))
        .unwrap();
    let after_revoke = request(&rotated, original_snapshot, [0x31; 16], "request-1", 2);
    let replay = fixture
        .with(&rotated, |current| {
            store.reserve_admin_command(current, &after_revoke)
        })
        .unwrap();
    assert_eq!(
        replay,
        ManagedPolicyCommandState::Committed(receipt.clone())
    );
    let repeated_commit = fixture
        .with(&rotated, |current| {
            store.commit_admin_command(current, &pending, &consent)
        })
        .unwrap();
    assert_eq!(
        repeated_commit,
        ManagedPolicyCommandState::Committed(receipt.clone())
    );
    let readback = fixture
        .with(&rotated, |current| {
            store.readback_admin_receipt(&current.authenticated_subject(), receipt.command_id())
        })
        .unwrap();
    assert_eq!(readback, Some(receipt.clone()));
    let cancel = fixture
        .with(&rotated, |current| {
            store.cancel_admin_command(current, receipt.command_id(), pending.semantic_digest())
        })
        .unwrap();
    assert_eq!(cancel, ManagedPolicyCommandState::Committed(receipt));

    let changed = ManagedPolicyCommandV1::new(
        [0x31; 16],
        "request-1",
        ProjectTrustProjectId::from_bytes(PROJECT),
        original_snapshot,
        rules(),
        2,
        &rotated,
        2,
    )
    .unwrap();
    assert!(matches!(
        fixture.with(&rotated, |current| store
            .reserve_admin_command(current, &changed)),
        Err(runne_application::project_trust::admin::AdminError::Conflict)
    ));
    let _ = path;
}
