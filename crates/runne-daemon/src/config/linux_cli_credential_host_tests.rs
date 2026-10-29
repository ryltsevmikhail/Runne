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

#[test]
fn installation_upgrade_accepts_only_pin_changes() {
    let make = |pin: &str, extra: &str| {
        let system: SystemConfig = toml::from_str(&format!(
            "schema_version=2\n{extra}\n[provider_activation]\nmode='deepseek_responses_text_v1'\nprofile_id='gocode-deepseek-responses-text/1'\nprofile_digest='0112c4b6ce64739810bb79802ebb5ae6fd8ac563d1d1397ac51f07a190538195'\n[linux_cli_credential_host]\ncli_sha256='{pin}'\ndaemon_sha256='{pin}'\nhost_sha256='{pin}'\n"
        )).unwrap();
        ConfigurationSnapshot::from_merge(
            &BuiltInDefaults::new(Path::new("/isolated-runtime")),
            &system,
            Path::new("/owner/config.toml"),
        )
        .unwrap()
    };
    let old = make(&"1".repeat(64), "");
    let next = make(&"2".repeat(64), "");
    assert_ne!(old.digest, next.digest);
    next.validate_cli_upgrade_from(&old).unwrap();
    for extra in [
        "max_in_flight=2",
        "db_path='/other/database'",
        "http_bind='127.0.0.1:9999'",
    ] {
        assert!(
            make(&"2".repeat(64), extra)
                .validate_cli_upgrade_from(&old)
                .is_err()
        );
    }
}
