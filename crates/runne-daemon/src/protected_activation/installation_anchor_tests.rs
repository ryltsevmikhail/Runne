use super::installation_anchor::{
    Fault, load_read_only, provision_after_provider_bound_v2, set_fault, test_guard,
};
use crate::bootstrap::bootstrap;
use crate::config::{BuiltInDefaults, ConfigurationSnapshot};
use std::fs;
use std::path::{Path, PathBuf};

fn configuration(root: &Path) -> ConfigurationSnapshot {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(root))
}

fn state_path(config: &ConfigurationSnapshot) -> PathBuf {
    Path::new(&config.replay_integrity_key_path)
        .with_file_name("native-enrollment-installation-v1.state")
}

#[test]
fn readonly_bootstrap_never_creates_an_installation_anchor() {
    let _guard = test_guard();
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path());
    let outcome = bootstrap(&config).unwrap();
    assert!(!state_path(&config).exists());
    assert!(load_read_only(&outcome).is_err());
    assert!(!state_path(&config).exists());
}

#[test]
fn v2_provision_and_restart_load_keep_one_stable_digest() {
    let _guard = test_guard();
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path());
    let outcome = bootstrap(&config).unwrap();
    runne_store::schema::ensure_event_log_lineage_id(&outcome.db_conn).unwrap();
    let first = provision_after_provider_bound_v2(&outcome).unwrap();
    assert_ne!(first.installation_identity_digest(), &[0; 32]);
    drop(outcome);
    let restart = bootstrap(&config).unwrap();
    let second = load_read_only(&restart).unwrap();
    assert_eq!(
        first.installation_identity_digest(),
        second.installation_identity_digest()
    );
}

#[test]
fn v2_only_adopts_a_complete_final_without_marker_and_rejects_substitution() {
    let _guard = test_guard();
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path());
    let outcome = bootstrap(&config).unwrap();
    runne_store::schema::ensure_event_log_lineage_id(&outcome.db_conn).unwrap();
    let path = state_path(&config);
    fs::write(path.with_extension("state.tmp"), b"orphan").unwrap();
    let first = provision_after_provider_bound_v2(&outcome).unwrap();
    outcome
        .db_conn
        .execute(
            "DELETE FROM _daemon_info WHERE key = 'native_enrollment_installation_v1'",
            [],
        )
        .unwrap();
    assert!(load_read_only(&outcome).is_err());
    assert_eq!(
        provision_after_provider_bound_v2(&outcome)
            .unwrap()
            .installation_identity_digest(),
        first.installation_identity_digest()
    );
    fs::remove_file(&path).unwrap();
    assert!(load_read_only(&outcome).is_err());
    assert!(provision_after_provider_bound_v2(&outcome).is_err());
}

#[test]
fn unix_file_shape_and_record_corruption_fail_closed() {
    let _guard = test_guard();
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path());
    let outcome = bootstrap(&config).unwrap();
    runne_store::schema::ensure_event_log_lineage_id(&outcome.db_conn).unwrap();
    let path = state_path(&config);
    provision_after_provider_bound_v2(&outcome).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_read_only(&outcome).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let hard_link = path.with_extension("hard-link");
    fs::hard_link(&path, &hard_link).unwrap();
    assert!(load_read_only(&outcome).is_err());
    fs::remove_file(&hard_link).unwrap();
    let mut zero_nonce = fs::read(&path).unwrap();
    zero_nonce[4..36].fill(0);
    fs::write(&path, zero_nonce).unwrap();
    assert!(load_read_only(&outcome).is_err());
    fs::write(&path, [0; 84]).unwrap();
    assert!(load_read_only(&outcome).is_err());
    let link = path.with_extension("link");
    symlink(&path, &link).unwrap();
    fs::rename(&link, &path).unwrap();
    assert!(load_read_only(&outcome).is_err());
}

#[test]
fn descriptor_rooted_faults_fail_closed_before_the_marker() {
    let _guard = test_guard();
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path());
    let outcome = bootstrap(&config).unwrap();
    runne_store::schema::ensure_event_log_lineage_id(&outcome.db_conn).unwrap();
    for fault in [Fault::Temp, Fault::Final] {
        set_fault(fault);
        assert!(provision_after_provider_bound_v2(&outcome).is_err());
        assert!(load_read_only(&outcome).is_err());
        let path = state_path(&config);
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
    set_fault(Fault::BeforeMarker);
    assert!(provision_after_provider_bound_v2(&outcome).is_err());
    assert!(load_read_only(&outcome).is_err());
    assert!(provision_after_provider_bound_v2(&outcome).is_ok());
}

#[test]
fn parent_path_substitution_cannot_publish_a_marker() {
    let _guard = test_guard();
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path());
    let outcome = bootstrap(&config).unwrap();
    runne_store::schema::ensure_event_log_lineage_id(&outcome.db_conn).unwrap();
    set_fault(Fault::Parent);
    assert!(provision_after_provider_bound_v2(&outcome).is_err());
    assert!(!state_path(&config).exists());
    assert!(
        outcome
            .db_conn
            .query_row(
                "SELECT value FROM _daemon_info WHERE key = 'native_enrollment_installation_v1'",
                [],
                |_| Ok(())
            )
            .is_err()
    );
}

#[test]
fn daemon_directory_replacement_after_bootstrap_cannot_publish_or_adopt() {
    let _guard = test_guard();
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path());
    let outcome = bootstrap(&config).unwrap();
    runne_store::schema::ensure_event_log_lineage_id(&outcome.db_conn).unwrap();
    let daemon_dir = Path::new(&config.db_path).parent().unwrap();
    let moved = daemon_dir.with_extension("moved");
    fs::rename(daemon_dir, &moved).unwrap();
    fs::create_dir(daemon_dir).unwrap();
    fs::set_permissions(daemon_dir, fs::Permissions::from_mode(0o700)).unwrap();

    assert!(provision_after_provider_bound_v2(&outcome).is_err());
    assert!(!state_path(&config).exists());
    assert!(
        outcome
            .db_conn
            .query_row(
                "SELECT value FROM _daemon_info WHERE key = 'native_enrollment_installation_v1'",
                [],
                |_| Ok(())
            )
            .is_err()
    );
}

#[test]
fn runtime_root_replacement_after_bootstrap_cannot_publish_or_adopt() {
    let _guard = test_guard();
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path());
    let outcome = bootstrap(&config).unwrap();
    runne_store::schema::ensure_event_log_lineage_id(&outcome.db_conn).unwrap();
    let runtime_dir = root.path().to_path_buf();
    let moved = runtime_dir.with_extension("moved");
    fs::rename(&runtime_dir, &moved).unwrap();
    fs::create_dir(&runtime_dir).unwrap();
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700)).unwrap();

    assert!(provision_after_provider_bound_v2(&outcome).is_err());
    assert!(load_read_only(&outcome).is_err());
    assert!(!state_path(&config).exists());
    assert!(
        outcome
            .db_conn
            .query_row(
                "SELECT value FROM _daemon_info WHERE key = 'native_enrollment_installation_v1'",
                [],
                |_| Ok(())
            )
            .is_err()
    );
    drop(outcome);
    fs::remove_dir(&runtime_dir).unwrap();
    fs::rename(moved, runtime_dir).unwrap();
}

#[test]
fn database_replacement_after_bootstrap_cannot_publish_or_adopt() {
    let _guard = test_guard();
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path());
    let outcome = bootstrap(&config).unwrap();
    runne_store::schema::ensure_event_log_lineage_id(&outcome.db_conn).unwrap();
    let database = Path::new(&config.db_path);
    let moved = database.with_extension("moved");
    fs::rename(database, &moved).unwrap();
    fs::write(database, b"replacement").unwrap();
    fs::set_permissions(database, fs::Permissions::from_mode(0o600)).unwrap();

    assert!(provision_after_provider_bound_v2(&outcome).is_err());
    assert!(load_read_only(&outcome).is_err());
    assert!(!state_path(&config).exists());
    assert!(
        outcome
            .db_conn
            .query_row(
                "SELECT value FROM _daemon_info WHERE key = 'native_enrollment_installation_v1'",
                [],
                |_| Ok(())
            )
            .is_err()
    );
}
