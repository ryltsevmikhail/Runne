//! First-launch installation on a machine with no previous Runne state.
use super::command;
use serde::Deserialize;
use std::path::{Path, PathBuf};

const DEEPSEEK_TEXT_PROFILE: &str = "gocode-deepseek-responses-text/1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstallationStatus {
    pub state: String,
    pub(super) runtime_root: PathBuf,
    pub(super) config_path: PathBuf,
    provider_profile: String,
}

/// Reads the fixed installation layout without writing anything.
pub(super) fn inspect(daemon: &Path) -> Result<InstallationStatus, String> {
    let status = command::invoke::<InstallationStatus>(daemon, &["terminal-adoption", "inspect"])?;
    validate(&status)?;
    Ok(status)
}

/// Publishes the exact empty first-launch layout measured by the daemon.
///
/// This never runs for an existing installation: adoption keeps its explicit
/// owner consent and is the only upgrade path.
pub(super) fn initialize(daemon: &Path, cli: &Path) -> Result<PathBuf, String> {
    let cli = cli
        .to_str()
        .ok_or("CLI path is not representable for first launch")?;
    let status =
        command::invoke::<InstallationStatus>(daemon, &["terminal-adoption", "init-fresh", cli])?;
    validate(&status)?;
    if status.provider_profile != DEEPSEEK_TEXT_PROFILE {
        return Err("Installation does not bind the released DeepSeek text profile".into());
    }
    Ok(status.runtime_root)
}

pub(super) fn validate(status: &InstallationStatus) -> Result<(), String> {
    if !status.runtime_root.is_absolute() || !status.config_path.is_absolute() {
        return Err("Installation layout is not absolute".into());
    }
    if !matches!(status.state.as_str(), "fresh" | "initialized" | "legacy") {
        return Err("Installation state is not recognized".into());
    }
    Ok(())
}
