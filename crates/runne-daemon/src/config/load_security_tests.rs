use super::{owner_private_config_metadata, read_explicit_config};
use std::os::unix::fs::{PermissionsExt as _, symlink};

#[test]
fn fixed_source_loader_accepts_only_owner_private_regular_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "schema_version=2").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(read_explicit_config(&path).unwrap(), "schema_version=2");

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(read_explicit_config(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.path().join("config-link.toml");
    symlink(&path, &link).unwrap();
    assert!(read_explicit_config(&link).is_err());
}

#[test]
fn fixed_source_loader_rejects_oversized_config_before_parsing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("large.toml");
    std::fs::write(&path, vec![b'x'; 16 * 1024 + 1]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_explicit_config(&path).is_err());
}

#[test]
fn owner_metadata_rejects_wrong_owner_and_non_regular_sources() {
    assert!(!owner_private_config_metadata(true, 10, 0o600, 11));
    assert!(!owner_private_config_metadata(false, 11, 0o600, 11));
    assert!(owner_private_config_metadata(true, 11, 0o600, 11));
}
