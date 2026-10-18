use super::ProjectTrustStore;
use super::current_fence::acquire_current;
use runne_application::project_trust::{
    ManagedEffectDecision, ProjectTrustEffectLease, ProjectTrustPersistence, ProjectTrustProjectId,
    ProjectTrustRecord, ProjectTrustStatus, TrustPersistenceError, TrustToken,
};
use rusqlite::params;
use std::path::{Path, PathBuf};

const AUTHORITY: [u8; 16] = [0x4a; 16];
const DEFAULT_PROJECT: ProjectTrustProjectId = ProjectTrustProjectId::from_bytes([0x71; 16]);
const LOCK_PROJECT: ProjectTrustProjectId = ProjectTrustProjectId::from_bytes([0x75; 16]);

fn stores() -> (tempfile::TempDir, ProjectTrustStore, ProjectTrustStore) {
    let root = tempfile::tempdir().unwrap();
    let canonical = canonical_path(root.path(), "event-log.sqlite");
    let first = ProjectTrustStore::open(&canonical, AUTHORITY).unwrap();
    let second = ProjectTrustStore::open(&canonical, AUTHORITY).unwrap();
    (root, first, second)
}

fn canonical_path(root: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let runtime = root.join("runtime");
    let daemon = runtime.join("daemon");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::create_dir(&daemon).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    daemon.join(name)
}

fn assert_route_parity(
    store: &ProjectTrustStore,
    project: ProjectTrustProjectId,
    expected: ProjectTrustRecord,
) {
    let factory = acquire_current(store, project).unwrap();
    assert_eq!(factory.record(), expected);
    let snapshot = factory.snapshot().unwrap();
    assert_eq!(snapshot.record, expected);
    assert!(snapshot.is_valid());
    assert_eq!(
        snapshot.policy.decisions(),
        [ManagedEffectDecision::Allow; 6]
    );
    drop(factory);

    let trait_route = store.acquire_effect_lease(project).unwrap();
    assert_eq!(trait_route.record(), expected);
    assert_eq!(trait_route.snapshot().unwrap(), snapshot);
    drop(trait_route);
}

#[test]
fn factory_and_trait_route_match_statuses_and_absent_default() {
    let (_root, store, _second) = stores();
    let epoch = store.instance_epoch().unwrap();
    let default = ProjectTrustRecord::untrusted_default(epoch);
    assert_route_parity(&store, DEFAULT_PROJECT, default);
    assert!(!store.has_explicit_record(DEFAULT_PROJECT).unwrap());
    let policy_exists: i64 = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_effect_policies WHERE project_id = ?1)",
            params![DEFAULT_PROJECT.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(policy_exists, 0);

    for (byte, status) in [
        (0x72, ProjectTrustStatus::Untrusted),
        (0x73, ProjectTrustStatus::Trusted),
        (0x74, ProjectTrustStatus::Managed),
    ] {
        let project = ProjectTrustProjectId::from_bytes([byte; 16]);
        let record = store
            .commit(project, status, 0, TrustToken::new(epoch, 0))
            .unwrap();
        assert_route_parity(&store, project, record);
    }
}

#[test]
fn missing_policy_failure_drops_the_begun_writer_fence() {
    let (_root, first, second) = stores();
    let epoch = first.instance_epoch().unwrap();
    let record = first
        .commit(
            DEFAULT_PROJECT,
            ProjectTrustStatus::Trusted,
            0,
            TrustToken::new(epoch, 0),
        )
        .unwrap();
    first
        .connection
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM managed_effect_policies WHERE project_id = ?1",
            params![DEFAULT_PROJECT.as_bytes().as_slice()],
        )
        .unwrap();
    second
        .connection
        .lock()
        .unwrap()
        .pragma_update(None, "busy_timeout", 25)
        .unwrap();

    assert!(matches!(
        acquire_current(&first, DEFAULT_PROJECT),
        Err(TrustPersistenceError::Unavailable)
    ));
    assert_eq!(
        second
            .commit(
                DEFAULT_PROJECT,
                ProjectTrustStatus::Untrusted,
                0,
                record.token(),
            )
            .unwrap()
            .status,
        ProjectTrustStatus::Untrusted
    );
}

#[test]
fn independent_writer_waits_for_factory_lease_drop() {
    let (_root, first, second) = stores();
    let epoch = first.instance_epoch().unwrap();
    let record = first
        .commit(
            LOCK_PROJECT,
            ProjectTrustStatus::Trusted,
            0,
            TrustToken::new(epoch, 0),
        )
        .unwrap();
    second
        .connection
        .lock()
        .unwrap()
        .pragma_update(None, "busy_timeout", 25)
        .unwrap();

    let lease = acquire_current(&first, LOCK_PROJECT).unwrap();
    assert_eq!(lease.record(), record);
    assert!(matches!(
        second.commit(
            LOCK_PROJECT,
            ProjectTrustStatus::Untrusted,
            0,
            record.token(),
        ),
        Err(TrustPersistenceError::Unavailable)
    ));
    drop(lease);
    assert_eq!(
        second
            .commit(
                LOCK_PROJECT,
                ProjectTrustStatus::Untrusted,
                0,
                record.token(),
            )
            .unwrap()
            .status,
        ProjectTrustStatus::Untrusted
    );
}

#[test]
fn factory_rejects_foreign_epoch_and_replaced_database_identity() {
    let (_root, owner, _second) = stores();
    let foreign_root = tempfile::tempdir().unwrap();
    let foreign = ProjectTrustStore::open(
        &canonical_path(foreign_root.path(), "other.sqlite"),
        AUTHORITY,
    )
    .unwrap();

    let mut foreign_epoch = owner.clone();
    foreign_epoch.instance_epoch = owner.instance_epoch + 1;
    assert!(acquire_current(&foreign_epoch, DEFAULT_PROJECT).is_err());

    let mut replacement = owner.clone();
    replacement.sidecar_path = foreign.sidecar_path.clone();
    replacement.instance_epoch = foreign.instance_epoch;
    assert!(acquire_current(&replacement, DEFAULT_PROJECT).is_err());
}
