use super::policy::{HostResult, ImagePolicy};
use std::path::Path;

/// Explicit owner-session upgrade; holds bootstrap locks across the store transition.
/// No daemon, HTTP client, or startup path invokes this operation automatically.
pub fn upgrade(previous_directory: &Path, previous_config: &Path) -> HostResult<()> {
    let after = crate::config::load_external_config()
        .map_err(|_| "current installation config unavailable")?;
    let before = crate::config::load_external_config_at(previous_config)
        .map_err(|_| "previous installation config unavailable")?;
    after
        .validate_cli_upgrade_from(&before)
        .map_err(|_| "upgrade must change only explicit installation pins")?;
    let current = ImagePolicy::load(&after)?;
    let previous = ImagePolicy::load_for_paths(
        &before,
        previous_config.to_owned(),
        previous_directory.join("runne"),
        previous_directory.join("runned"),
        previous_directory.join("runne-credential-host"),
    )?;
    current.revalidate()?;
    let bootstrap = crate::bootstrap::bootstrap(&after)
        .map_err(|_| "upgrade requires a stopped runtime and exclusive bootstrap locks")?;
    // Repeat both image/config measurements after acquiring exclusive runtime ownership.
    current.revalidate()?;
    let checked = crate::config::load_external_config_at(previous_config)
        .map_err(|_| "previous installation config changed")?;
    let measured = ImagePolicy::load_for_paths(
        &checked,
        previous_config.to_owned(),
        previous.cli.clone(),
        previous.daemon.clone(),
        previous.host.clone(),
    )?;
    if measured.manifest != previous.manifest {
        return Err("previous installation changed during upgrade");
    }
    crate::canonical_provider::upgrade_cli_installation(&before, &after, bootstrap).map_err(
        |_| "installation transition unconfirmed; retain both versions and retry the same upgrade",
    )
}
