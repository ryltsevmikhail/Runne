use super::*;
use std::os::unix::fs::PermissionsExt;
#[test]
fn terminal_source_requires_exact_config_and_original_images() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.path().join("data");
    let bin = directory.path().join("bin");
    let config_directory = directory.path().join("config/runne-daemon");
    for path in [&root, &bin, &config_directory] {
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = config_directory.join("config.toml");
    std::fs::write(&config, "synthetic configuration").unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cli = bin.join("runne");
    let daemon = bin.join("runned");
    let host = bin.join("runne-credential-host");
    for path in [&cli, &daemon, &host] {
        std::fs::write(path, b"synthetic executable").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    publish_terminal_installation_source(&root, &config, &cli, &daemon, &host).unwrap();
    let store = ActivationStateStore::open(&root).unwrap();
    let source = load(&store).unwrap().unwrap();
    assert_eq!(source.daemon, daemon);
    let mut command = Command::new(&daemon);
    command.env_clear();
    apply(&mut command, &store).unwrap();
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
    apply(&mut child, &store).unwrap();
    let output = child.output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, root.as_os_str().as_encoded_bytes());
    assert!(
        command
            .get_envs()
            .any(|(key, value)| key == "XDG_CONFIG_HOME"
                && value == Some(directory.path().join("config").as_os_str()))
    );
    std::fs::write(&config, "changed configuration").unwrap();
    assert!(load(&store).is_err());
    let previous = directory.path().join("previous.toml");
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
    apply(&mut command, &state).unwrap();
    assert!(
        !command
            .get_envs()
            .any(|(key, _)| key == "XDG_RUNTIME_DIR" || key == "XDG_CONFIG_HOME")
    );
}
