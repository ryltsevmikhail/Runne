//! Explicit finite tool grant opt-in, preserving existing primary authority rows.
use super::*;
use crate::linux_cli_credential_host::policy::ImagePolicy;

/// The previous config is a private snapshot of the exact adopted source.
/// Only an absent-to-finite tool budget is permitted; image pins and all other policy stay exact.
pub fn repin_tools(
    previous_config: &Path,
    expected_manifest: &str,
) -> Result<TerminalAdoptionPreview, DaemonError> {
    let before = crate::config::load_external_config_at(previous_config)?;
    let (after, images, root) = verified_target()?;
    validate_tool_delta(&before, &after)?;
    if hex::encode(images.manifest) != expected_manifest {
        return Err(failure("tool opt-in manifest changed"));
    }
    let old_images = ImagePolicy::load_for_paths(
        &before,
        previous_config.to_owned(),
        images.cli.clone(),
        images.daemon.clone(),
        images.host.clone(),
    )
    .map_err(failure)?;
    old_images.revalidate().map_err(failure)?;
    if old_images.cli_digest != images.cli_digest
        || old_images.daemon_digest != images.daemon_digest
        || old_images.host_digest != images.host_digest
    {
        return Err(failure("tool opt-in cannot change image pins"));
    }
    let bootstrap = crate::bootstrap::bootstrap(&after)?;
    images.revalidate().map_err(failure)?;
    old_images.revalidate().map_err(failure)?;
    if !adopted_connection(&after, &root, &bootstrap.db_conn)? {
        return Err(failure(
            "tool opt-in requires the exact protected installation",
        ));
    }
    require_idle(&bootstrap.db_conn)?;
    // Existing primary provider authority/budgets are read-only here. The separately
    // bounded tool profile grant is installed by verified protected startup.
    runne_platform_desktop::repin_terminal_configuration(
        &root,
        previous_config,
        &crate::config::external_config_path(),
    )
    .map_err(|_| failure("tool source repin uncertain; retry the same previous snapshot"))?;
    drop(bootstrap);
    prepare()
}

fn validate_tool_delta(
    before: &ConfigurationSnapshot,
    after: &ConfigurationSnapshot,
) -> Result<(), DaemonError> {
    if before.d2_safe_tool_loop_budget.is_some()
        || after
            .d2_safe_tool_loop_budget
            .and_then(|budget| budget.limits())
            .is_none()
        || before.secondary_profile_catalog.is_some()
        || after.secondary_profile_catalog.is_some()
        || after.with_d2_tool_budget_from(before).digest != before.digest
    {
        return Err(failure(
            "tool opt-in must change only an absent finite tool budget",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_tool_opt_in_rejects_unrelated_changes_and_budget_renewal() {
        let before =
            ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(Path::new("/synthetic")));
        let mut after = before.clone();
        after.d2_safe_tool_loop_budget = Some(
            serde_json::from_value(serde_json::json!({
                "token_budget_limit": 1000, "cost_budget_limit_micros": 100
            }))
            .unwrap(),
        );
        assert!(validate_tool_delta(&before, &after).is_ok());
        let mut changed = after.clone();
        changed.db_path = "/different/event-log.db".into();
        assert!(validate_tool_delta(&before, &changed).is_err());
        assert!(validate_tool_delta(&after, &after).is_err());
        assert!(validate_tool_delta(&before, &before).is_err());
    }
}

pub(super) fn require_idle(connection: &rusqlite::Connection) -> Result<(), DaemonError> {
    let idle: bool = connection.query_row(
        "SELECT active=1 AND capability_allowed=1 AND approval_allowed=1
         AND capability_revocation_observed=0 AND approval_revocation_observed=0
         AND token_budget_reserved=0 AND cost_budget_reserved_micros=0
         AND activation_binding_kind='protected_v2'
         AND NOT EXISTS(SELECT 1 FROM provider_dispatch_attempts WHERE state NOT IN (2,5))
         AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox WHERE state=1)
         AND NOT EXISTS(SELECT 1 FROM provider_credential_operations
             WHERE state NOT IN ('COMPLETED','FAILED','EXPIRED','CANCELLED','TOMBSTONED')
             OR (native_effect_disposition='POSSIBLE_EFFECT' AND state!='COMPLETED'))
         AND NOT EXISTS(SELECT 1 FROM provider_credential_verification_observations WHERE state='LEASED')
         AND NOT EXISTS(SELECT 1 FROM provider_credential_authority_heads WHERE hard_fence_disposition IS NOT NULL
             OR release_migration_state IN ('PENDING','VERIFIED'))
         FROM provider_runtime_authority_state WHERE id=1",
        [], |row| row.get(0),
    ).map_err(|_| failure("tool opt-in authority unavailable"))?;
    if !idle {
        return Err(failure("tool opt-in requires idle unrevoked authority"));
    }
    Ok(())
}
