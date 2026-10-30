use super::*;
use std::os::unix::fs::PermissionsExt;

#[cfg(target_os = "macos")]
fn replace_executable(path: &Path, bytes: &[u8]) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).unwrap();
}
#[test]
fn terminal_source_requires_exact_config_and_original_images() {
    let directory = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(directory.path()).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = base.join("data");
    let bin = base.join("bin");
    let config_directory = base.join("config/runne-daemon");
    for path in [&root, &bin, &config_directory] {
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = config_directory.join("config.toml");
    std::fs::write(&config, "synthetic configuration").unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cli = bin.join("runne");
    let daemon = bin.join("runned");
    let host = if cfg!(target_os = "macos") {
        cli.clone()
    } else {
        bin.join("runne-credential-host")
    };
    for path in [&cli, &daemon, &host] {
        if path.exists() {
            continue;
        }
        std::fs::write(path, b"synthetic executable").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    publish_terminal_installation_source(&root, &config, &cli, &daemon, &host).unwrap();
    let store = ActivationStateStore::open(&root).unwrap();
    let source = load(&store).unwrap().unwrap();
    assert_eq!(source.daemon, daemon);
    #[cfg(target_os = "linux")]
    {
        let mut command = Command::new(&daemon);
        command.env_clear();
        apply(&mut command, &store, None).unwrap();
        assert!(
            command
                .get_envs()
                .any(|(key, value)| key == "XDG_RUNTIME_DIR" && value == Some(root.as_os_str())),
            "adopted child must resolve omitted database/key paths under the verified root"
        );
        let mut child = Command::new("/bin/sh");
        child
            .env_clear()
            .args(["-c", "printf %s \"$XDG_RUNTIME_DIR\""]);
        apply(&mut child, &store, None).unwrap();
        let output = child.output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, root.as_os_str().as_encoded_bytes());
        assert!(
            command
                .get_envs()
                .any(|(key, value)| key == "XDG_CONFIG_HOME"
                    && value == Some(base.join("config").as_os_str()))
        );
    }
    std::fs::write(&config, "changed configuration").unwrap();
    assert!(load(&store).is_err());
    let previous = base.join("previous.toml");
    std::fs::write(&previous, "synthetic configuration").unwrap();
    std::fs::set_permissions(&previous, std::fs::Permissions::from_mode(0o600)).unwrap();
    repin_terminal_configuration(&root, &previous, &config).unwrap();
    repin_terminal_configuration(&root, &previous, &config).unwrap();
    assert!(load(&store).is_ok());
    std::fs::write(&previous, "wrong predecessor").unwrap();
    assert!(repin_terminal_configuration(&root, &previous, &config).is_err());
    std::fs::write(&config, "second unauthorized mutation").unwrap();
    assert!(load(&store).is_err());
}

#[test]
fn ordinary_root_does_not_forward_terminal_environment() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = ActivationStateStore::open(directory.path()).unwrap();
    let mut command = Command::new("/bin/true");
    command.env_clear();
    apply(&mut command, &state, None).unwrap();
    assert!(
        !command
            .get_envs()
            .any(|(key, _)| key == "XDG_RUNTIME_DIR" || key == "XDG_CONFIG_HOME")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_home_is_derived_only_from_the_fixed_application_support_layout() {
    assert_eq!(
        macos_home_for(Path::new("/Users/owner/Library/Application Support")).unwrap(),
        PathBuf::from("/Users/owner")
    );
    assert!(macos_home_for(Path::new("/Users/owner/Library")).is_err());
    assert!(macos_home_for(Path::new("/Users/owner/config")).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn rebuilt_images_rebind_only_after_the_retained_predecessor_is_proven() {
    let directory = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(directory.path()).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = base.join("data");
    let bin = base.join("bin");
    let config_directory = base.join("config/runne-daemon");
    for path in [&root, &bin, &config_directory] {
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = config_directory.join("config.toml");
    std::fs::write(&config, "synthetic configuration").unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cli = bin.join("runne");
    let daemon = bin.join("runned");
    std::fs::write(&cli, b"adopted cli").unwrap();
    std::fs::write(&daemon, b"adopted daemon").unwrap();
    for path in [&cli, &daemon] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    publish_terminal_installation_source(&root, &config, &cli, &daemon, &cli).unwrap();
    let store = ActivationStateStore::open(&root).unwrap();
    replace_executable(&cli, b"rebuilt cli");
    replace_executable(&daemon, b"rebuilt daemon");
    assert!(
        prepare_launch(&store).is_err(),
        "a rebuild without the retained predecessor is not an in-place update"
    );
    // The launcher stages every image it opens, so an installed product always
    // retains the exact predecessor bytes under the runtime root.
    let previous_cli = ExecutableIdentityV1::measure(&cli).unwrap();
    assert!(previous_cli.byte_length() > 0);
    // Restore the adopted bytes to stage them, then rebuild again.
    replace_executable(&cli, b"adopted cli");
    replace_executable(&daemon, b"adopted daemon");
    let adopted_cli = ExecutableIdentityV1::measure(&cli).unwrap();
    let adopted_daemon = ExecutableIdentityV1::measure(&daemon).unwrap();
    store.stage_trusted_executable(&cli, &adopted_cli).unwrap();
    store
        .stage_trusted_executable(&daemon, &adopted_daemon)
        .unwrap();
    replace_executable(&cli, b"rebuilt cli");
    replace_executable(&daemon, b"rebuilt daemon");
    let prepared = prepare_launch(&store).unwrap();
    let (previous, next) = prepared.image_upgrade.unwrap();
    assert!(prepared.current.is_some());
    store.migrate_installation_images(&previous, &next).unwrap();
    assert!(load(&store).is_ok(), "rebind publishes the measured images");
    store.migrate_installation_images(&previous, &next).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn changed_configuration_blocks_an_otherwise_valid_image_rebind() {
    let directory = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(directory.path()).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = base.join("data");
    let bin = base.join("bin");
    let config_directory = base.join("config/runne-daemon");
    for path in [&root, &bin, &config_directory] {
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = config_directory.join("config.toml");
    std::fs::write(&config, "synthetic configuration").unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cli = bin.join("runne");
    let daemon = bin.join("runned");
    for (path, bytes) in [(&cli, b"adopted cli".as_slice()), (&daemon, b"adopted daemon")] {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    publish_terminal_installation_source(&root, &config, &cli, &daemon, &cli).unwrap();
    let store = ActivationStateStore::open(&root).unwrap();
    let adopted_cli = ExecutableIdentityV1::measure(&cli).unwrap();
    let adopted_daemon = ExecutableIdentityV1::measure(&daemon).unwrap();
    store.stage_trusted_executable(&cli, &adopted_cli).unwrap();
    store
        .stage_trusted_executable(&daemon, &adopted_daemon)
        .unwrap();
    std::fs::write(&config, "mutated configuration").unwrap();
    assert!(prepare_launch(&store).is_err());
}
