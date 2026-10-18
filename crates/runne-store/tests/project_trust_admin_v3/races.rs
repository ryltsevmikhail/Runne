use std::{
    path::Path,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use runne_application::project_trust::{
    ProjectTrustPersistence,
    admin::{AdminError, ManagedPolicyCommandState, verify_managed_policy_consent_v1},
};
use runne_store::ProjectTrustStore;

use super::support::{
    AUTHORITY, AcceptConsent, AdminFixture, PROJECT, canonical, now_ms, request, session, snapshot,
    trusted_store,
};

#[test]
fn register_checks_deadline_after_waiting_for_t1_writer() {
    let root = tempfile::tempdir().unwrap();
    let path = canonical(root.path(), "register-lock.sqlite");
    let store = ProjectTrustStore::open(&path, AUTHORITY).unwrap();
    let deadline = now_ms() + 2_000;
    let binding = session(1, 1, deadline);
    let fixture = Arc::new(AdminFixture::new(binding.clone()));
    let bootstrap = fixture.bootstrap(&binding);
    let lease = store
        .acquire_effect_lease(
            runne_application::project_trust::ProjectTrustProjectId::from_bytes(PROJECT),
        )
        .unwrap();
    let thread_store = store.clone();
    let thread_fixture = fixture.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        thread_fixture.with(&binding, |current| {
            started_tx.send(()).unwrap();
            thread_store.register_admin(current, &bootstrap)
        })
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    sleep_until(deadline + 30);
    drop(lease);
    assert!(matches!(worker.join().unwrap(), Err(AdminError::Expired)));
    let connection = raw_sidecar(&path);
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM managed_policy_administrator",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn reserve_checks_deadline_after_waiting_for_t1_writer() {
    let root = tempfile::tempdir().unwrap();
    let (_path, store) = trusted_store(root.path(), "reserve-lock.sqlite");
    let bootstrap_binding = session(1, 1, now_ms() + 60_000);
    let fixture = Arc::new(AdminFixture::new(bootstrap_binding.clone()));
    super::support::register(&store, &fixture, &bootstrap_binding);
    let deadline = now_ms() + 2_000;
    let binding = session(2, 2, deadline);
    fixture.update(binding.clone());
    let command = request(&binding, snapshot(&store), [0x61; 16], "waited-reserve", 1);
    let lease = store
        .acquire_effect_lease(
            runne_application::project_trust::ProjectTrustProjectId::from_bytes(PROJECT),
        )
        .unwrap();
    let thread_store = store.clone();
    let thread_fixture = fixture.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        thread_fixture.with(&binding, |current| {
            started_tx.send(()).unwrap();
            thread_store.reserve_admin_command(current, &command)
        })
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    sleep_until(deadline + 30);
    drop(lease);
    assert!(matches!(worker.join().unwrap(), Err(AdminError::Expired)));
    let connection = raw_sidecar_for_store(root.path(), "reserve-lock.sqlite");
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM managed_policy_admin_commands",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn commit_checks_deadline_after_waiting_for_t1_writer() {
    let root = tempfile::tempdir().unwrap();
    let (_path, store) = trusted_store(root.path(), "commit-lock.sqlite");
    let registered = session(1, 1, now_ms() + 60_000);
    let fixture = Arc::new(AdminFixture::new(registered.clone()));
    super::support::register(&store, &fixture, &registered);
    let deadline = now_ms() + 2_500;
    let binding = session(2, 2, deadline);
    fixture.update(binding.clone());
    let snapshot = snapshot(&store);
    let request = request(&binding, snapshot, [0x62; 16], "waited-commit", 1);
    let pending = match fixture
        .with(&binding, |current| {
            store.reserve_admin_command(current, &request)
        })
        .unwrap()
    {
        ManagedPolicyCommandState::Pending(command) => command,
        state => panic!("expected pending command, got {state:?}"),
    };
    let consent = fixture
        .with(&binding, |current| {
            verify_managed_policy_consent_v1(current, &pending, b"test-only proof", &AcceptConsent)
        })
        .unwrap();
    let lease = store
        .acquire_effect_lease(
            runne_application::project_trust::ProjectTrustProjectId::from_bytes(PROJECT),
        )
        .unwrap();
    let thread_store = store.clone();
    let thread_fixture = fixture.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        thread_fixture.with(&binding, |current| {
            started_tx.send(()).unwrap();
            thread_store.commit_admin_command(current, &pending, &consent)
        })
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    sleep_until(deadline + 30);
    drop(lease);
    assert!(matches!(
        worker.join().unwrap(),
        Ok(ManagedPolicyCommandState::Expired)
    ));
    let connection = raw_sidecar_for_store(root.path(), "commit-lock.sqlite");
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM managed_policy_admin_commands WHERE command_id=?1",
                [&[0x62_u8; 16][..]],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        4
    );
    assert_eq!(
        store
            .load(runne_application::project_trust::ProjectTrustProjectId::from_bytes(PROJECT))
            .unwrap()
            .revision,
        snapshot.record.revision
    );
}

fn sleep_until(deadline: i64) {
    while now_ms() <= deadline {
        thread::sleep(Duration::from_millis(5));
    }
}

fn raw_sidecar(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(format!("{}.project-trust", path.display())).unwrap()
}

fn raw_sidecar_for_store(root: &Path, name: &str) -> rusqlite::Connection {
    raw_sidecar(&canonical(root, name))
}
