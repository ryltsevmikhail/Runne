use super::*;
use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus,
};

const AUTHORITY: [u8; 16] = [0x4a; 16];
const PROJECT: ProjectTrustProjectId = ProjectTrustProjectId::from_bytes([0x71; 16]);

fn stores() -> (tempfile::TempDir, ProjectTrustStore, ProjectTrustStore) {
    let root = tempfile::tempdir().unwrap();
    let canonical = canonical_path(root.path(), "event-log.sqlite");
    let first = ProjectTrustStore::open(&canonical, AUTHORITY).unwrap();
    let second = ProjectTrustStore::open(&canonical, AUTHORITY).unwrap();
    (root, first, second)
}

fn canonical_path(root: &std::path::Path, name: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let runtime = root.join("runtime");
    let daemon = runtime.join("daemon");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::create_dir(&daemon).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    daemon.join(name)
}

#[test]
fn effect_lease_fences_revoke_from_independent_store_until_drop() {
    let (_root, first, second) = stores();
    let epoch = first.instance_epoch().unwrap();
    let trusted = first
        .commit(
            PROJECT,
            ProjectTrustStatus::Trusted,
            0,
            runne_application::project_trust::TrustToken::new(epoch, 0),
        )
        .unwrap();
    let lease = first.acquire_effect_lease(PROJECT).unwrap();
    assert_eq!(lease.record(), trusted);

    second
        .connection
        .lock()
        .unwrap()
        .pragma_update(None, "busy_timeout", 25)
        .unwrap();
    assert!(
        second
            .commit(PROJECT, ProjectTrustStatus::Untrusted, 0, trusted.token())
            .is_err()
    );
    assert_eq!(first.load(PROJECT).unwrap(), trusted);
    drop(lease); // cancellation/drop releases the durable writer fence
    let revoked = second
        .commit(PROJECT, ProjectTrustStatus::Untrusted, 0, trusted.token())
        .unwrap();
    assert_eq!(revoked.status, ProjectTrustStatus::Untrusted);
    assert_eq!(first.load(PROJECT).unwrap(), revoked);
}

#[test]
fn effect_lease_denies_replaced_sidecar_identity_and_epoch() {
    let (_root, first, _second) = stores();
    let other_root = tempfile::tempdir().unwrap();
    let other = ProjectTrustStore::open(
        &canonical_path(other_root.path(), "other.sqlite"),
        AUTHORITY,
    )
    .unwrap();

    let mut recreated_epoch = first.clone();
    recreated_epoch.sidecar_path = other.sidecar_path.clone();
    assert!(recreated_epoch.acquire_effect_lease(PROJECT).is_err());

    let mut replaced_identity = first.clone();
    replaced_identity.sidecar_path = other.sidecar_path.clone();
    replaced_identity.instance_epoch = other.instance_epoch;
    assert!(replaced_identity.acquire_effect_lease(PROJECT).is_err());
}
