use super::*;

fn configuration(cli: &str, daemon: &str) -> Result<ConfigurationSnapshot, DaemonError> {
    let system: SystemConfig = toml::from_str(&format!(
        "schema_version=2\n[linux_cli_credential_host]\ncli_sha256='{cli}'\ndaemon_sha256='{daemon}'\nhost_sha256='{daemon}'\n"
    ))?;
    ConfigurationSnapshot::from_merge(
        &BuiltInDefaults::new(Path::new("/isolated-runtime")),
        &system,
        Path::new("/owner/config.toml"),
    )
}
#[test]
fn explicit_cli_pins_are_validated_and_participate_in_config_digest() {
    let first = configuration(&"1".repeat(64), &"2".repeat(64)).unwrap();
    let changed = configuration(&"3".repeat(64), &"2".repeat(64)).unwrap();
    assert_ne!(first.digest, changed.digest);
    assert!(first.linux_cli_credential_host.is_some());
    for invalid in [
        "".to_owned(),
        "0".repeat(64),
        "x".repeat(64),
        "a".repeat(63),
    ] {
        assert!(configuration(&invalid, &"2".repeat(64)).is_err());
    }
}
