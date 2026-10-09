use runne_store::ProjectTrustStore;
use std::path::{Path, PathBuf};

pub fn canonical_path(root: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let runtime = root.join("runtime");
    let daemon = runtime.join("daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    daemon.join(name)
}

pub fn trusted_store(root: &Path, name: &str) -> (PathBuf, ProjectTrustStore, [u8; 16]) {
    use runne_application::project_trust::{
        ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus, TrustToken,
    };

    let canonical = canonical_path(root, name);
    let authority = [0x4a; 16];
    let project = [0x71; 16];
    let store = ProjectTrustStore::open(&canonical, authority).unwrap();
    let epoch = store.instance_epoch().unwrap();
    store
        .commit(
            ProjectTrustProjectId::from_bytes(project),
            ProjectTrustStatus::Trusted,
            0,
            TrustToken::new(epoch, 0),
        )
        .unwrap();
    (canonical, store, project)
}

pub fn set_fixture_rules(canonical: &Path, decisions: [i64; 6]) {
    let connection =
        rusqlite::Connection::open(format!("{}.project-trust", canonical.display())).unwrap();
    connection
        .execute(
            "UPDATE managed_effect_policies SET fs_read=?2, fs_create=?3, fs_write=?4,
             fs_delete=?5, process_start=?6, network_use=?7 WHERE project_id=?1",
            rusqlite::params![
                &[0x71_u8; 16][..],
                decisions[0],
                decisions[1],
                decisions[2],
                decisions[3],
                decisions[4],
                decisions[5]
            ],
        )
        .unwrap();
}
