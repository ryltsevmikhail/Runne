//! Explicit stopped-runtime image update; authority and policy remain unchanged.
use super::{
    ConfigurationSnapshot, DaemonError, ImagePolicy, Path, TerminalAdoptionPreview,
    adopted_connection, failure, prepare, repin, verified_target,
};

pub fn upgrade_images(
    previous_directory: &Path,
    previous_config: &Path,
    expected_manifest: &str,
) -> Result<TerminalAdoptionPreview, DaemonError> {
    let before = crate::config::load_external_config_at(previous_config)?;
    let (after, images, root) = verified_target()?;
    validate_delta(&before, &after)?;
    if hex::encode(images.manifest) != expected_manifest {
        return Err(failure("protected image upgrade manifest changed"));
    }
    let previous = ImagePolicy::load_for_paths(
        &before,
        previous_config.to_owned(),
        previous_directory.join("runne"),
        previous_directory.join("runned"),
        previous_directory.join("runne-credential-host"),
    )
    .map_err(failure)?;
    let bootstrap = crate::bootstrap::bootstrap(&after)?;
    if !bootstrap.db_existed || !adopted_connection(&after, &root, &bootstrap.db_conn)? {
        return Err(failure(
            "image upgrade requires the exact adopted protected installation",
        ));
    }
    images.revalidate().map_err(failure)?;
    // The old release cannot be revalidated as this executing process; measure it
    // again by exact retained paths and compare its complete pinned manifest.
    let checked = crate::config::load_external_config_at(previous_config)?;
    let measured = ImagePolicy::load_for_paths(
        &checked,
        previous_config.to_owned(),
        previous.cli.clone(),
        previous.daemon.clone(),
        previous.host.clone(),
    )
    .map_err(failure)?;
    if measured.manifest != previous.manifest {
        return Err(failure("previous protected installation changed"));
    }
    repin::require_idle(&bootstrap.db_conn)?;
    runne_platform_desktop::upgrade_terminal_installation_source(
        &root,
        previous_config,
        previous_directory,
        &crate::config::external_config_path(),
        images
            .daemon
            .parent()
            .ok_or_else(|| failure("image directory unavailable"))?,
    )
    .map_err(|_| {
        failure("protected source upgrade uncertain; retry exact predecessor and manifest")
    })?;
    drop(bootstrap);
    prepare()
}

fn validate_delta(
    before: &ConfigurationSnapshot,
    after: &ConfigurationSnapshot,
) -> Result<(), DaemonError> {
    if after.with_d2_tool_budget_from(before).digest != after.digest {
        return Err(failure("image upgrade cannot change finite tool grants"));
    }
    let mut absent = before.clone();
    absent.d2_safe_tool_loop_budget = None;
    // The existing pins-only validator intentionally accepts only absent budgets.
    // Normalize both equally without changing the live snapshots or persisted policy.
    after
        .with_d2_tool_budget_from(&absent)
        .validate_cli_upgrade_from(&before.with_d2_tool_budget_from(&absent))
}

#[cfg(test)]
mod tests {
    use super::super::BuiltInDefaults;
    use super::*;
    fn configured(pin: &str, tokens: u64) -> ConfigurationSnapshot {
        let text = format!(
            "schema_version=2\n[provider_activation]\nmode='deepseek_responses_text_v1'\nprofile_id='gocode-deepseek-responses-text/1'\nprofile_digest='0112c4b6ce64739810bb79802ebb5ae6fd8ac563d1d1397ac51f07a190538195'\n[linux_cli_credential_host]\ncli_sha256='{pin}'\ndaemon_sha256='{pin}'\nhost_sha256='{pin}'\n[d2_safe_tool_loop_budget]\ntoken_budget_limit={tokens}\ncost_budget_limit_micros=4000000\n"
        );
        let system: crate::config::SystemConfig = toml::from_str(&text).unwrap();
        ConfigurationSnapshot::from_merge(
            &BuiltInDefaults::new(Path::new("/synthetic")),
            &system,
            Path::new("/synthetic/config.toml"),
        )
        .unwrap()
    }

    #[test]
    fn image_update_accepts_only_pins_with_identical_finite_budget() {
        let before = configured(&"1".repeat(64), 1000000);
        let after = configured(&"2".repeat(64), 1000000);
        assert!(validate_delta(&before, &after).is_ok());
        assert!(validate_delta(&before, &configured(&"2".repeat(64), 2000000)).is_err());
    }

    #[test]
    fn image_update_never_renews_tool_budget_or_changes_runtime_policy() {
        let mut before =
            ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(Path::new("/synthetic")));
        before.d2_safe_tool_loop_budget = Some(
            serde_json::from_value(serde_json::json!({
                "token_budget_limit": 1000000, "cost_budget_limit_micros": 4000000
            }))
            .unwrap(),
        );
        let mut changed = before.clone();
        changed.d2_safe_tool_loop_budget = None;
        assert!(validate_delta(&before, &changed).is_err());
        changed = before.clone();
        changed.db_path = "/other/event-log.db".into();
        assert!(validate_delta(&before, &changed).is_err());
    }
}
