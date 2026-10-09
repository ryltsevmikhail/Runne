use runne_application::project_trust::{
    ProjectTrustPersistence,
    admin::{ManagedPolicyCommandState, verify_managed_policy_consent_v1},
};
use runne_store::ProjectTrustStore;

use super::support::{
    AUTHORITY, AcceptConsent, AdminFixture, canonical, now_ms, request, session, snapshot,
};

#[test]
fn lost_ack_duplicate_survives_file_reopen_and_session_rotation() {
    let root = tempfile::tempdir().unwrap();
    let path = canonical(root.path(), "reopen.sqlite");
    let store = ProjectTrustStore::open(&path, AUTHORITY).unwrap();
    let epoch = store.instance_epoch().unwrap();
    store
        .commit(
            runne_application::project_trust::ProjectTrustProjectId::from_bytes([0x71; 16]),
            runne_application::project_trust::ProjectTrustStatus::Trusted,
            0,
            runne_application::project_trust::TrustToken::new(epoch, 0),
        )
        .unwrap();
    let original = session(1, 1, now_ms() + 60_000);
    let fixture = AdminFixture::new(original.clone());
    super::support::register(&store, &fixture, &original);
    let old_snapshot = snapshot(&store);
    let command = request(&original, old_snapshot, [0x51; 16], "lost-ack", 1);
    let pending = match fixture
        .with(&original, |current| {
            store.reserve_admin_command(current, &command)
        })
        .unwrap()
    {
        ManagedPolicyCommandState::Pending(command) => command,
        state => panic!("expected pending command, got {state:?}"),
    };
    let receipt = match fixture
        .with(&original, |current| {
            let proof = verify_managed_policy_consent_v1(
                current,
                &pending,
                b"test-only proof",
                &AcceptConsent,
            )?;
            store.commit_admin_command(current, &pending, &proof)
        })
        .unwrap()
    {
        ManagedPolicyCommandState::Committed(receipt) => receipt,
        state => panic!("expected committed receipt, got {state:?}"),
    };
    drop(store);

    let reopened = ProjectTrustStore::open(&path, AUTHORITY).unwrap();
    let rotated = session(2, 2, now_ms() + 60_000);
    fixture.update(rotated.clone());
    let duplicate = request(&rotated, old_snapshot, [0x51; 16], "lost-ack", 1);
    let replay = fixture
        .with(&rotated, |current| {
            reopened.reserve_admin_command(current, &duplicate)
        })
        .unwrap();
    assert_eq!(replay, ManagedPolicyCommandState::Committed(receipt));
}
