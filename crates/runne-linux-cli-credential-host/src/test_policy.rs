use super::policy::ImagePolicy;
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
pub fn policy(directory: &Path) -> ImagePolicy {
    let daemon = std::env::current_exe().unwrap().canonicalize().unwrap();
    let cli = directory.join("runne");
    std::fs::write(&cli, b"synthetic-cli-image").unwrap();
    std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o700)).unwrap();
    let cli_digest = hex::encode(Sha256::digest(std::fs::read(&cli).unwrap()));
    let daemon_digest = hex::encode(Sha256::digest(std::fs::read(&daemon).unwrap()));
    let config_path = directory.join("config.toml");
    std::fs::write(&config_path, format!("schema_version=2\n[linux_cli_credential_host]\ncli_sha256='{cli_digest}'\ndaemon_sha256='{daemon_digest}'\nhost_sha256='{daemon_digest}'\n")).unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = runne_daemon::config::load_external_config_at(&config_path).unwrap();
    ImagePolicy::load_for_paths(&config, config_path, cli, daemon.clone(), daemon).unwrap()
}
#[test]
fn image_and_config_drift_close_access() {
    let directory =
        tempfile::tempdir_in(std::env::current_exe().unwrap().parent().unwrap()).unwrap();
    let first = policy(directory.path());
    assert!(first.revalidate().is_ok());
    std::fs::write(&first.cli, b"changed-image").unwrap();
    assert!(first.revalidate().is_err());
    let second = policy(directory.path());
    std::fs::write(directory.path().join("config.toml"), "schema_version=2\n").unwrap();
    assert!(second.revalidate().is_err());
}
