//! First launch on a machine with no previous Runne installation.
//!
//! Adoption upgrades an existing standalone installation; it must never be the
//! only way into the terminal client. This module inspects the fixed layout and,
//! for an empty machine, publishes the exact owner-private configuration and
//! measured installation source that the protected launcher needs.

use super::failure;
use crate::config::{self, BuiltInDefaults, ConfigurationSnapshot};
use crate::error::DaemonError;
use runne_api::{ProviderActivationBindingV1, ProviderActivationModeV1};
use serde::Serialize;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct InstallationStatus {
    /// `fresh`, `initialized` or `legacy`; see [`installation_state`].
    pub state: &'static str,
    pub runtime_root: PathBuf,
    pub config_path: PathBuf,
    pub provider_profile: String,
}

const ACTIVATION_DIRECTORY: &str = ".desktop-protected-activation";
const INSTALLATION_SOURCE: &str = "terminal-installation-v1.json";

/// Distinguishes the three entry states instead of treating any database as an
/// adopted installation: a protected binding is what the terminal client owns.
fn installation_state(snapshot: &ConfigurationSnapshot, root: &Path) -> &'static str {
    // The published source is the terminal client's own marker: adoption and
    // first launch write it, a legacy standalone database never has it.
    let activation = root.join(ACTIVATION_DIRECTORY);
    if activation.join(INSTALLATION_SOURCE).is_file() {
        "initialized"
    } else if Path::new(&snapshot.db_path).is_file() {
        "legacy"
    } else {
        "fresh"
    }
}

/// Reports the fixed layout without writing anything.
pub fn inspect() -> Result<InstallationStatus, DaemonError> {
    let snapshot = config::load_external_config()?;
    let config_path = config::external_config_path();
    let root = root_of(&snapshot)?;
    Ok(status(&snapshot, &root, config_path))
}

/// Initializes exactly the empty layout; refuses any existing installation.
pub fn initialize_fresh(cli: &Path) -> Result<InstallationStatus, DaemonError> {
    let config_path = config::external_config_path();
    let before = config::load_external_config()?;
    if Path::new(&before.db_path).exists() {
        return Err(failure("initialize requires an empty installation"));
    }
    ensure_private_directory(
        config_path
            .parent()
            .ok_or_else(|| failure("initialized configuration path unavailable"))?,
    )?;
    let binding = ProviderActivationBindingV1::deepseek_responses_text_v1();
    write_config_if_absent(&config_path, &binding)?;
    let snapshot = config::load_external_config()?;
    verify_binding(&snapshot, &binding)?;
    let root = root_of(&snapshot)?;
    let defaults = BuiltInDefaults::new(&root);
    if snapshot.db_path != defaults.db_path
        || snapshot.replay_integrity_key_path != defaults.replay_integrity_key_path
    {
        return Err(failure(
            "initialized configuration is not the default layout",
        ));
    }
    runne_platform_desktop::require_terminal_baseline_root(&root)
        .map_err(|_| failure("initialized runtime root is not owner-private"))?;
    let cli = fs::canonicalize(cli).map_err(|_| failure("initialized CLI image unavailable"))?;
    let daemon = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| failure("initialized daemon image unavailable"))?;
    runne_platform_desktop::publish_terminal_installation_source(
        &root,
        &config_path,
        &cli,
        &daemon,
        &cli,
    )
    .map_err(|_| failure("initialized installation source unavailable"))?;
    Ok(status(&snapshot, &root, config_path))
}

fn status(
    snapshot: &ConfigurationSnapshot,
    root: &Path,
    config_path: PathBuf,
) -> InstallationStatus {
    InstallationStatus {
        state: installation_state(snapshot, root),
        runtime_root: root.to_owned(),
        config_path,
        provider_profile: snapshot
            .provider_activation
            .binding()
            .profile_id()
            .to_owned(),
    }
}

fn root_of(snapshot: &ConfigurationSnapshot) -> Result<PathBuf, DaemonError> {
    let database = Path::new(&snapshot.db_path);
    let root = database
        .parent()
        .and_then(Path::parent)
        .filter(|root| root.is_absolute())
        .ok_or_else(|| failure("initialized runtime layout unavailable"))?;
    Ok(root.to_owned())
}

fn ensure_private_directory(path: &Path) -> Result<(), DaemonError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(failure("initialized configuration directory unavailable"));
    }
    if !path.exists() {
        let mut builder = DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(path)
            .map_err(|_| failure("initialized configuration directory unavailable"))?;
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| failure("initialized configuration directory unavailable"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(failure("initialized configuration directory unavailable"));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| failure("initialized configuration directory unavailable"))
}

fn write_config_if_absent(
    path: &Path,
    binding: &ProviderActivationBindingV1,
) -> Result<(), DaemonError> {
    let body = config_body(binding);
    let temporary = path.with_file_name(format!(".config-{}.tmp", uuid::Uuid::now_v7()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| failure("initialized configuration source unavailable"))?;
    file.write_all(body.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| failure("initialized configuration source unavailable"))?;
    drop(file);
    if path.exists() {
        // A concurrent or previous attempt already published a source; keep it
        // and let the caller verify the exact binding instead of overwriting.
        let _ = fs::remove_file(&temporary);
        return Ok(());
    }
    if fs::rename(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(failure("initialized configuration source unavailable"));
    }
    sync_directory(
        path.parent()
            .ok_or_else(|| failure("initialized configuration directory unavailable"))?,
    )
}

fn sync_directory(path: &Path) -> Result<(), DaemonError> {
    let directory = fs::File::open(path)
        .map_err(|_| failure("initialized configuration directory unavailable"))?;
    directory
        .sync_all()
        .map_err(|_| failure("initialized configuration directory unavailable"))
}

/// Exact non-secret first-launch source: the released `DeepSeek` text profile
/// with no credential, so the client opens and can offer enrollment.
fn config_body(binding: &ProviderActivationBindingV1) -> String {
    format!(
        "schema_version = 2\n\n[provider_activation]\nmode = \"{}\"\nprofile_id = \"{}\"\nprofile_digest = \"{}\"\n",
        binding.mode().as_str(),
        binding.profile_id(),
        hex::encode(binding.profile_digest())
    )
}

fn verify_binding(
    snapshot: &ConfigurationSnapshot,
    expected: &ProviderActivationBindingV1,
) -> Result<(), DaemonError> {
    let actual = snapshot.provider_activation.binding();
    if actual.mode() != ProviderActivationModeV1::DeepSeekResponsesTextV1
        || actual.profile_id() != expected.profile_id()
        || actual.profile_digest() != expected.profile_digest()
    {
        return Err(failure(
            "initialized configuration does not bind the released DeepSeek text profile",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_body_is_the_released_deepseek_text_binding() {
        let binding = ProviderActivationBindingV1::deepseek_responses_text_v1();
        let body = config_body(&binding);
        assert!(body.contains("schema_version = 2"));
        assert!(body.contains("mode = \"deepseek_responses_text_v1\""));
        assert!(body.contains("profile_id = \"gocode-deepseek-responses-text/1\""));
        assert!(body.contains(&hex::encode(binding.profile_digest())));
        assert!(!body.contains("deterministic"));
    }

    #[test]
    fn config_body_parses_into_the_same_binding() {
        let binding = ProviderActivationBindingV1::deepseek_responses_text_v1();
        let body = config_body(&binding);
        let system: crate::config::SystemConfig = toml::from_str(&body).unwrap();
        let defaults = BuiltInDefaults::new(Path::new("/private/runne-test"));
        let snapshot = ConfigurationSnapshot::from_merge(
            &defaults,
            &system,
            Path::new("/private/runne-test/config.toml"),
        )
        .unwrap();
        verify_binding(&snapshot, &binding).unwrap();
        assert_eq!(
            snapshot.provider_activation.binding().profile_id(),
            "gocode-deepseek-responses-text/1"
        );
    }
}
