use super::*;
use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus, TrustPersistenceError,
};

const AUTHORITY: [u8; 16] = [0x3a; 16];
const PROJECT: ProjectTrustProjectId = ProjectTrustProjectId::from_bytes([0x62; 16]);

fn fixture(root: &std::path::Path, name: &str) -> ProjectTrustStore {
    use std::os::unix::fs::PermissionsExt as _;
    let runtime = root.join("runtime");
    let daemon = runtime.join("daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    ProjectTrustStore::open(&daemon.join(name), AUTHORITY).unwrap()
}

#[test]
fn control_lease_commits_once_and_rejects_stale_replay() {
    let root = tempfile::tempdir().unwrap();
    let store = fixture(root.path(), "runtime.sqlite");
    let observed = store.load(PROJECT).unwrap();
    let mut control = store.acquire_control_lease(PROJECT).unwrap();
    let trusted = control.decide(true, observed.token()).unwrap();
    assert_eq!(trusted.status, ProjectTrustStatus::Trusted);
    assert_eq!(trusted.revision, 1);
    drop(control);

    let mut replay = store.acquire_control_lease(PROJECT).unwrap();
    assert!(matches!(
        replay.decide(false, observed.token()),
        Err(TrustPersistenceError::Conflict { current: 1, .. })
    ));
    drop(replay);
    assert_eq!(store.load(PROJECT).unwrap(), trusted);
}

#[test]
fn control_lease_refuses_managed_state_and_mask() {
    let root = tempfile::tempdir().unwrap();
    let store = fixture(root.path(), "runtime.sqlite");
    let record = store.load(PROJECT).unwrap();
    let managed = store
        .commit(PROJECT, ProjectTrustStatus::Managed, 3, record.token())
        .unwrap();
    let mut lease = store.acquire_control_lease(PROJECT).unwrap();
    assert!(matches!(
        lease.decide(false, managed.token()),
        Err(TrustPersistenceError::Unavailable)
    ));
    drop(lease);
    assert_eq!(store.load(PROJECT).unwrap(), managed);
}

#[test]
fn concurrent_opposite_decisions_have_one_winner() {
    let root = tempfile::tempdir().unwrap();
    let first = fixture(root.path(), "runtime.sqlite");
    let second = ProjectTrustStore::open(
        &root.path().join("runtime/daemon/runtime.sqlite"),
        AUTHORITY,
    )
    .unwrap();
    let token = first.load(PROJECT).unwrap().token();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let run =
        |store: ProjectTrustStore, trusted: bool, gate: std::sync::Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                gate.wait();
                let mut lease = store.acquire_control_lease(PROJECT).unwrap();
                lease.decide(trusted, token)
            })
        };
    let left = run(first.clone(), true, std::sync::Arc::clone(&barrier));
    let right = run(second, false, std::sync::Arc::clone(&barrier));
    barrier.wait();
    let outcomes = [left.join().unwrap(), right.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|value| value.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, Err(TrustPersistenceError::Conflict { .. })))
            .count(),
        1
    );
    assert_eq!(first.load(PROJECT).unwrap().revision, 1);
}

#[test]
fn retained_authority_fails_closed_after_sidecar_path_replacement() {
    let root = tempfile::tempdir().unwrap();
    let old = fixture(root.path(), "runtime.sqlite");
    let old_record = old.load(PROJECT).unwrap();
    let trusted = old
        .commit(PROJECT, ProjectTrustStatus::Trusted, 0, old_record.token())
        .unwrap();
    let replacement = fixture(root.path(), "replacement.sqlite");
    let sidecar = old.sidecar_path.clone();
    let moved = sidecar.with_extension("project-trust.replaced");
    std::fs::rename(&sidecar, &moved).unwrap();
    std::fs::copy(&replacement.sidecar_path, &sidecar).unwrap();

    assert!(old.load(PROJECT).is_err());
    assert!(
        old.commit(PROJECT, ProjectTrustStatus::Untrusted, 0, trusted.token())
            .is_err()
    );
    assert!(old.acquire_effect_lease(PROJECT).is_err());
    assert!(old.acquire_control_lease(PROJECT).is_err());
}
