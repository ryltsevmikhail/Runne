//! Exact, crash-recoverable source-witness replacement under exclusive runtime ownership.
use super::{
    ActivationCheckpoint, ActivationStateStore, Deserialize, LaunchTestControls, OpenOptions,
    OpenOptionsExt, Path, ProtectedBundledRuntimeError, RECORD, Serialize, TerminalSource, Write,
    config_hash, measured, require_linux_cli_baseline_root, sync_directory,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageTransition {
    before: TerminalSource,
    after: TerminalSource,
}

/// Replaces only the measured installation source after daemon policy validation.
///
/// The caller must hold bootstrap locks and verify unchanged protected authority,
/// policy and finite budgets. This function neither creates consent nor changes DB state.
///
/// # Errors
/// Rejects an unrelated predecessor, changed retained images or conflicting replay.
pub fn upgrade_terminal_installation_source(
    root: &Path,
    previous_config: &Path,
    previous_directory: &Path,
    current_config: &Path,
    current_directory: &Path,
) -> Result<(), ProtectedBundledRuntimeError> {
    require_linux_cli_baseline_root(root)?;
    let state = ActivationStateStore::open(root)?;
    let invalid = ProtectedBundledRuntimeError::ActivationStateUnavailable;
    let actual: TerminalSource = state.read_record(RECORD)?.ok_or(invalid)?;
    let old_hash = config_hash(previous_config)?;
    let new_hash = config_hash(current_config)?;
    if old_hash == new_hash || previous_directory == current_directory {
        return Err(invalid);
    }
    // Journal name binds the exact predecessor; it is immutable and durable before CAS.
    let journal_name = format!("terminal-image-upgrade-{}.json", hex_digest(&old_hash));
    let saved: Option<ImageTransition> = state.read_record(&journal_name)?;
    let before = saved
        .as_ref()
        .map_or_else(|| actual.clone(), |v| v.before.clone());
    if before.config != current_config
        || before.config_sha256 != old_hash
        || before.cli != previous_directory.join("runne")
        || before.daemon != previous_directory.join("runned")
        || before.host != previous_directory.join("runne-credential-host")
        || measured(&before.cli)? != before.cli_image
        || measured(&before.daemon)? != before.daemon_image
        || measured(&before.host)? != before.host_image
    {
        return Err(invalid);
    }
    let mut after = before.clone();
    after.config_sha256 = new_hash;
    after.cli = current_directory.join("runne");
    after.daemon = current_directory.join("runned");
    after.host = current_directory.join("runne-credential-host");
    after.cli_image = measured(&after.cli)?;
    after.daemon_image = measured(&after.daemon)?;
    after.host_image = measured(&after.host)?;
    after.validate()?;
    let transition = ImageTransition { before, after };
    if saved.as_ref().is_some_and(|v| v != &transition)
        || (actual != transition.before && actual != transition.after)
    {
        return Err(invalid);
    }
    state.persist_record_exact(
        &journal_name,
        &transition,
        ActivationCheckpoint::AfterFinalPinFileSync,
        &mut LaunchTestControls::production(),
    )?;
    if actual == transition.after {
        return Ok(());
    }
    let encoded = serde_json::to_vec(&transition.after).map_err(|_| invalid)?;
    let temporary = state
        .directory
        .join(format!(".terminal-image-{}.tmp", uuid::Uuid::now_v7()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| invalid)?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| invalid)?;
    if state.read_record::<TerminalSource>(RECORD)? != Some(transition.before) {
        let _ = std::fs::remove_file(&temporary);
        return Err(invalid);
    }
    std::fs::rename(&temporary, state.directory.join(RECORD)).map_err(|_| invalid)?;
    sync_directory(&state.directory)
}

fn hex_digest(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    digest
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            write!(text, "{byte:02x}").expect("writing to String cannot fail");
            text
        })
}

#[cfg(test)]
mod tests {
    use super::super::{load, publish_terminal_installation_source, repin_terminal_configuration};
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn exact_image_upgrade_is_replayable_and_preserves_tool_consent_chain() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = temp.path().join("runtime");
        let old = temp.path().join("old");
        let new = temp.path().join("new");
        let config_dir = temp.path().join("config/runne-daemon");
        for dir in [&root, &old, &new, &config_dir] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for dir in [&old, &new] {
            for name in ["runne", "runned", "runne-credential-host"] {
                let path = dir.join(name);
                std::fs::write(&path, dir.to_string_lossy().as_bytes()).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).unwrap();
            }
        }
        let config = config_dir.join("config.toml");
        let initial = temp.path().join("initial.toml");
        let previous = temp.path().join("previous.toml");
        for path in [&config, &initial, &previous] {
            std::fs::write(path, b"initial").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        publish_terminal_installation_source(
            &root,
            &config,
            &old.join("runne"),
            &old.join("runned"),
            &old.join("runne-credential-host"),
        )
        .unwrap();
        std::fs::write(&config, b"finite tool consent").unwrap();
        repin_terminal_configuration(&root, &initial, &config).unwrap();
        std::fs::write(&previous, b"finite tool consent").unwrap();
        let store = ActivationStateStore::open(&root).unwrap();
        let consent = load(&store).unwrap().unwrap().previous_config_sha256;
        std::fs::write(&config, b"new images same policy").unwrap();
        assert!(load(&store).is_err());
        assert!(
            upgrade_terminal_installation_source(&root, &initial, &old, &config, &new).is_err()
        );
        upgrade_terminal_installation_source(&root, &previous, &old, &config, &new).unwrap();
        upgrade_terminal_installation_source(&root, &previous, &old, &config, &new).unwrap();
        // Simulate restart after journal fsync but before witness rename.
        let name = format!(
            "terminal-image-upgrade-{}.json",
            hex_digest(&config_hash(&previous).unwrap())
        );
        let journal: ImageTransition = store.read_record(&name).unwrap().unwrap();
        std::fs::write(
            store.directory.join(RECORD),
            serde_json::to_vec(&journal.before).unwrap(),
        )
        .unwrap();
        upgrade_terminal_installation_source(&root, &previous, &old, &config, &new).unwrap();
        let source = load(&store).unwrap().unwrap();
        assert_eq!(source.previous_config_sha256, consent);
        assert_eq!(source.daemon, new.join("runned"));
        std::fs::write(&config, b"different update").unwrap();
        assert!(
            upgrade_terminal_installation_source(&root, &previous, &old, &config, &new).is_err()
        );
    }
}
