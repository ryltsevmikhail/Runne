use runne_application::project_trust::{
    ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId,
    admin::{ManagedPolicyCommandState, ManagedPolicyCommandV1, verify_managed_policy_consent_v1},
};

use super::support::{
    AUTHORITY, AcceptConsent, AdminFixture, PROJECT, canonical, now_ms, request, rules, session,
    snapshot, trusted_store,
};

#[test]
fn reserve_requires_an_explicit_project_and_cancel_is_terminal() {
    use runne_application::project_trust::{
        ProjectTrustPersistence, admin::ManagedPolicyRoleState,
    };
    let root = tempfile::tempdir().unwrap();
    let path = canonical(root.path(), "no-record.sqlite");
    let store = runne_store::ProjectTrustStore::open(&path, AUTHORITY).unwrap();
    let binding = session(1, 1, now_ms() + 60_000);
    let fixture = AdminFixture::new(binding.clone());
    super::support::register(&store, &fixture, &binding);
    assert_eq!(
        fixture
            .with(&binding, |current| store.admin_role_state(current))
            .unwrap(),
        ManagedPolicyRoleState::Active { generation: 1 }
    );
    let missing = ProjectTrustEffectPolicySnapshot {
        record: runne_application::project_trust::ProjectTrustRecord::untrusted_default(
            store.instance_epoch().unwrap(),
        ),
        policy: runne_application::project_trust::ManagedEffectPolicyV1::all_allow(),
    };
    assert!(
        ManagedPolicyCommandV1::new(
            [0x41; 16],
            "missing",
            ProjectTrustProjectId::from_bytes(PROJECT),
            missing,
            rules(),
            1,
            &binding,
            1
        )
        .is_err()
    );
    assert!(
        !store
            .has_explicit_record(ProjectTrustProjectId::from_bytes(PROJECT))
            .unwrap()
    );
}

#[test]
fn pending_cancel_and_stale_cas_are_terminal_without_reissue() {
    use runne_application::project_trust::{
        ProjectTrustPersistence, ProjectTrustStatus, TrustToken,
    };
    let root = tempfile::tempdir().unwrap();
    let (_path, store) = trusted_store(root.path(), "terminal.sqlite");
    let binding = session(1, 1, now_ms() + 60_000);
    let fixture = AdminFixture::new(binding.clone());
    super::support::register(&store, &fixture, &binding);
    let initial = snapshot(&store);
    let cancelled_request = request(&binding, initial, [0x63; 16], "cancel-once", 1);
    let cancelled = match fixture
        .with(&binding, |current| {
            store.reserve_admin_command(current, &cancelled_request)
        })
        .unwrap()
    {
        ManagedPolicyCommandState::Pending(command) => command,
        state => panic!("expected pending command, got {state:?}"),
    };
    let state = fixture
        .with(&binding, |current| {
            store.cancel_admin_command(current, cancelled.command_id(), cancelled.semantic_digest())
        })
        .unwrap();
    assert_eq!(state, ManagedPolicyCommandState::Cancelled);
    assert_eq!(
        fixture
            .with(&binding, |current| store
                .reserve_admin_command(current, &cancelled_request))
            .unwrap(),
        ManagedPolicyCommandState::Cancelled
    );

    let stale_request = request(&binding, initial, [0x64; 16], "stale-cas", 1);
    fixture
        .with(&binding, |current| {
            store.reserve_admin_command(current, &stale_request)
        })
        .unwrap();
    store
        .commit(
            ProjectTrustProjectId::from_bytes(PROJECT),
            ProjectTrustStatus::Managed,
            17,
            TrustToken::new(initial.record.instance_epoch, initial.record.revision),
        )
        .unwrap();
    assert_eq!(
        fixture
            .with(&binding, |current| store
                .reserve_admin_command(current, &stale_request))
            .unwrap(),
        ManagedPolicyCommandState::Invalidated
    );
}

#[test]
fn wrong_nonce_or_consent_rolls_back_all_commit_effects() {
    use runne_application::project_trust::{ProjectTrustPersistence, admin::AdminError};
    let root = tempfile::tempdir().unwrap();
    let (path, store) = trusted_store(root.path(), "rollback.sqlite");
    let binding = session(1, 1, now_ms() + 60_000);
    let fixture = AdminFixture::new(binding.clone());
    super::support::register(&store, &fixture, &binding);
    let initial = snapshot(&store);
    let request_a = request(&binding, initial, [0x65; 16], "exact-a", 1);
    let request_b = request(&binding, initial, [0x66; 16], "exact-b", 1);
    let pending_a = match fixture
        .with(&binding, |current| {
            store.reserve_admin_command(current, &request_a)
        })
        .unwrap()
    {
        ManagedPolicyCommandState::Pending(command) => command,
        state => panic!("expected pending command, got {state:?}"),
    };
    let pending_b = match fixture
        .with(&binding, |current| {
            store.reserve_admin_command(current, &request_b)
        })
        .unwrap()
    {
        ManagedPolicyCommandState::Pending(command) => command,
        state => panic!("expected pending command, got {state:?}"),
    };
    let consent_a = fixture
        .with(&binding, |current| {
            verify_managed_policy_consent_v1(
                current,
                &pending_a,
                b"test-only proof",
                &AcceptConsent,
            )
        })
        .unwrap();
    let consent_b = fixture
        .with(&binding, |current| {
            verify_managed_policy_consent_v1(
                current,
                &pending_b,
                b"test-only proof",
                &AcceptConsent,
            )
        })
        .unwrap();
    assert!(matches!(
        fixture.with(&binding, |current| store
            .commit_admin_command(current, &pending_a, &consent_b)),
        Err(AdminError::Rejected)
    ));
    let wrong_nonce = pending_a
        .request()
        .issued_by_store(
            *pending_a.challenge_id(),
            [0xbb; 32],
            pending_a.issued_at_unix_ms(),
            pending_a.expires_at_unix_ms(),
            binding.session_expires_at_unix_ms(),
        )
        .unwrap();
    assert!(matches!(
        fixture.with(&binding, |current| store.commit_admin_command(
            current,
            &wrong_nonce,
            &consent_a
        )),
        Err(AdminError::Conflict)
    ));
    assert_eq!(
        store
            .load(ProjectTrustProjectId::from_bytes(PROJECT))
            .unwrap()
            .revision,
        initial.record.revision
    );
    assert_eq!(snapshot(&store).policy, initial.policy);
    let connection =
        rusqlite::Connection::open(format!("{}.project-trust", path.display())).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM managed_policy_admin_receipts",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM managed_policy_admin_commands WHERE state=1",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
}
