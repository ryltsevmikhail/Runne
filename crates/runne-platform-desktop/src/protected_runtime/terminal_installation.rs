//! Measured standalone source for adopted terminal runtimes.
use super::{
    ActivationCheckpoint, ActivationStateStore, Command, Deserialize, ExecutableIdentityV1,
    LaunchTestControls, OpenOptions, OpenOptionsExt, Path, PathBuf, ProtectedBundledRuntimeError,
    Read, Serialize, StoredExecutableV1, Write, require_linux_cli_baseline_root, sync_directory,
    validate_executable_path, validate_owner_private_file,
};
use sha2::{Digest, Sha256};

const RECORD: &str = "terminal-installation-v1.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalSource {
    version: u8,
    config: PathBuf,
    config_sha256: [u8; 32],
    previous_config_sha256: Option<[u8; 32]>,
    cli: PathBuf,
    cli_image: StoredExecutableV1,
    daemon: PathBuf,
    daemon_image: StoredExecutableV1,
    host: PathBuf,
    host_image: StoredExecutableV1,
}

/// Publishes only measured original installation paths after runtime adoption.
///
/// The daemon caller must already hold the exclusive runtime locks and consent.
///
/// # Errors
/// Rejects changed image/config bindings or unavailable owner-private state.
pub fn publish_terminal_installation_source(
    root: &Path,
    config: &Path,
    cli: &Path,
    daemon: &Path,
    host: &Path,
) -> Result<(), ProtectedBundledRuntimeError> {
    require_linux_cli_baseline_root(root)?;
    let source = TerminalSource {
        version: 1,
        config: config.to_owned(),
        config_sha256: config_hash(config)?,
        previous_config_sha256: None,
        cli: cli.to_owned(),
        cli_image: measured(cli)?,
        daemon: daemon.to_owned(),
        daemon_image: measured(daemon)?,
        host: host.to_owned(),
        host_image: measured(host)?,
    };
    source.validate()?;
    ActivationStateStore::open(root)?.persist_record_exact(
        RECORD,
        &source,
        ActivationCheckpoint::AfterFinalPinFileSync,
        &mut LaunchTestControls::production(),
    )
}

fn measured(path: &Path) -> Result<StoredExecutableV1, ProtectedBundledRuntimeError> {
    let canonical = validate_executable_path(path)?;
    if canonical != path {
        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
    }
    ExecutableIdentityV1::measure(path)
        .map(|value| StoredExecutableV1::from_contract(&value))
        .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)
}

fn config_hash(path: &Path) -> Result<[u8; 32], ProtectedBundledRuntimeError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    validate_owner_private_file(&file)?;
    if file
        .metadata()
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?
        .len()
        > 16 * 1024
    {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    if bytes.len() > 16 * 1024 {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    Ok(Sha256::digest(bytes).into())
}

impl TerminalSource {
    fn validate(&self) -> Result<(), ProtectedBundledRuntimeError> {
        let invalid = ProtectedBundledRuntimeError::ActivationStateUnavailable;
        let config_home = self.config.parent().and_then(Path::parent).ok_or(invalid)?;
        if self.version != 1
            || !config_home.is_absolute()
            || self.config != config_home.join("runne-daemon/config.toml")
            || self.cli.parent() != self.daemon.parent()
            || self.host.parent() != self.daemon.parent()
            || self.cli.file_name() != Some(std::ffi::OsStr::new("runne"))
            || self.daemon.file_name() != Some(std::ffi::OsStr::new("runned"))
            || self.host.file_name() != Some(std::ffi::OsStr::new("runne-credential-host"))
            || config_hash(&self.config)? != self.config_sha256
            || measured(&self.cli)? != self.cli_image
            || measured(&self.daemon)? != self.daemon_image
            || measured(&self.host)? != self.host_image
        {
            return Err(invalid);
        }
        Ok(())
    }
}

fn load(
    state: &ActivationStateStore,
) -> Result<Option<TerminalSource>, ProtectedBundledRuntimeError> {
    let source: Option<TerminalSource> = state.read_record(RECORD)?;
    if let Some(source) = &source {
        source.validate()?;
    }
    Ok(source)
}

pub(super) fn select(
    state: &ActivationStateStore,
    path: &Path,
    trusted: &ExecutableIdentityV1,
    provider_bound: bool,
) -> Result<Option<(PathBuf, ExecutableIdentityV1)>, ProtectedBundledRuntimeError> {
    let Some(source) = load(state)? else {
        return Ok(None);
    };
    if !provider_bound
        || path != source.daemon
        || &source.daemon_image.into_contract()? != trusted
        || state.load_stable()?.is_none()
    {
        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
    }
    // Native launcher still opens and retains this exact executable before spawn,
    // measures it again after spawn, and authenticates the inherited launch channel.
    Ok(Some((path.to_owned(), trusted.clone())))
}

pub(super) fn apply(
    command: &mut Command,
    state: &ActivationStateStore,
) -> Result<(), ProtectedBundledRuntimeError> {
    if let Some(source) = load(state)? {
        let config_home = source
            .config
            .parent()
            .and_then(Path::parent)
            .ok_or(ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
        let runtime_root = state
            .directory
            .parent()
            .ok_or(ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
        require_linux_cli_baseline_root(runtime_root)?;
        command.env("XDG_CONFIG_HOME", config_home);
        // Reproduce defaults of the adopted source after env_clear. This is
        // the verified launch root, never the caller's ambient XDG value.
        command.env("XDG_RUNTIME_DIR", runtime_root);
    }
    Ok(())
}

#[cfg(test)]
#[path = "terminal_installation_tests.rs"]
mod tests;

/// Exact one-time post-adoption config repin after daemon policy validation.
///
/// The caller holds runtime locks and verifies the sole permitted finite-tool-budget delta.
///
/// # Errors
/// Rejects changed image/config bindings or unavailable owner-private state.
pub fn repin_terminal_configuration(
    root: &Path,
    previous_config: &Path,
    current_config: &Path,
) -> Result<(), ProtectedBundledRuntimeError> {
    require_linux_cli_baseline_root(root)?;
    let store = ActivationStateStore::open(root)?;
    let previous: TerminalSource = store
        .read_record(RECORD)?
        .ok_or(ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    let old_hash = config_hash(previous_config)?;
    let next_hash = config_hash(current_config)?;
    if previous.config != current_config || old_hash == next_hash {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    if previous.config_sha256 == next_hash && previous.previous_config_sha256 == Some(old_hash) {
        return previous.validate();
    }
    if previous.config_sha256 != old_hash || previous.previous_config_sha256.is_some() {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    let mut next = previous.clone();
    next.config_sha256 = next_hash;
    next.previous_config_sha256 = Some(old_hash);
    next.validate()?;
    let encoded = serde_json::to_vec(&next)
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    let temporary = store
        .directory
        .join(format!(".terminal-repin-{}.tmp", uuid::Uuid::now_v7()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    if store.read_record::<TerminalSource>(RECORD)? != Some(previous) {
        let _ = std::fs::remove_file(&temporary);
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    std::fs::rename(&temporary, store.directory.join(RECORD))
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    sync_directory(&store.directory)
}

/// Validates the adopted source, including all pins, without exporting its material.
///
/// # Errors
/// Rejects changed image/config bindings or unavailable owner-private state.
pub fn verify_terminal_installation_source(
    root: &Path,
    config: &Path,
) -> Result<(), ProtectedBundledRuntimeError> {
    require_linux_cli_baseline_root(root)?;
    let state = ActivationStateStore::open(root)?;
    let source = load(&state)?.ok_or(ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    if source.config != config {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    Ok(())
}

mod image_upgrade;
pub use image_upgrade::upgrade_terminal_installation_source;
