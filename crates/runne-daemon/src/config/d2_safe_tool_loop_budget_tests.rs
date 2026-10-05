use super::*;

#[test]
fn d2_tool_grant_requires_explicit_finite_owner_budget() {
    let dir = tempfile::tempdir().unwrap();
    let defaults = BuiltInDefaults::new(dir.path());
    let absent: SystemConfig = toml::from_str("schema_version=2").unwrap();
    let explicit: SystemConfig = toml::from_str(
        "schema_version=2\n[d2_safe_tool_loop_budget]\ntoken_budget_limit=12000\ncost_budget_limit_micros=400000\n",
    )
    .unwrap();
    let absent =
        ConfigurationSnapshot::from_merge(&defaults, &absent, &external_config_path()).unwrap();
    let explicit =
        ConfigurationSnapshot::from_merge(&defaults, &explicit, &external_config_path()).unwrap();
    assert!(absent.d2_safe_tool_loop_budget.is_none());
    assert_eq!(
        explicit.d2_safe_tool_loop_budget.unwrap().limits(),
        Some((12000, 400000))
    );
    assert_ne!(absent.digest, explicit.digest);
    assert_eq!(
        explicit.provenance["d2_safe_tool_loop_budget"].source,
        Source::SystemFile
    );
}

#[test]
fn d2_tool_grant_rejects_zero_or_unknown_budget_fields() {
    let dir = tempfile::tempdir().unwrap();
    let defaults = BuiltInDefaults::new(dir.path());
    let zero: SystemConfig = toml::from_str(
        "schema_version=2\n[d2_safe_tool_loop_budget]\ntoken_budget_limit=0\ncost_budget_limit_micros=400000\n",
    )
    .unwrap();
    assert!(ConfigurationSnapshot::from_merge(&defaults, &zero, &external_config_path()).is_err());
    assert!(toml::from_str::<SystemConfig>(
        "schema_version=2\n[d2_safe_tool_loop_budget]\ntoken_budget_limit=12000\ncost_budget_limit_micros=400000\nautomatic_fallback=true\n"
    )
    .is_err());
}

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[test]
fn protected_d2_copy_imports_only_budget_and_preserves_absent_digest() {
    let dir = tempfile::tempdir().unwrap();
    let defaults = BuiltInDefaults::new(dir.path());
    let protected = ConfigurationSnapshot::from_defaults(&defaults);
    let absent: SystemConfig = toml::from_str("schema_version=2").unwrap();
    let configured: SystemConfig = toml::from_str(
        &format!("schema_version=2\ndb_path='external.db'\nhttp_bind='0.0.0.0:9'\nreplay_integrity_key_path='external.key'\nmax_in_flight=1\nshutdown_timeout_ms=1\n[provider_activation]\nmode='native_text_v1'\nprofile_id='{}'\nprofile_digest='{}'\n[provider_activation.settings]\naccounting_mode='payg'\n[d2_safe_tool_loop_budget]\ntoken_budget_limit=12000\ncost_budget_limit_micros=400000\n", runne_api::NATIVE_MINIMAX_PROFILE_ID, hex::encode(runne_api::NATIVE_MINIMAX_PROFILE_DIGEST)),
    )
    .unwrap();
    let absent =
        ConfigurationSnapshot::from_merge(&defaults, &absent, &external_config_path()).unwrap();
    let configured =
        ConfigurationSnapshot::from_merge(&defaults, &configured, &external_config_path()).unwrap();
    let absent_copy = protected.with_d2_tool_budget_from(&absent);
    assert_eq!(absent_copy.digest, protected.digest);
    assert!(absent_copy.d2_safe_tool_loop_budget.is_none());
    let configured_copy = protected.with_d2_tool_budget_from(&configured);
    assert_ne!(configured_copy.digest, protected.digest);
    assert_eq!(configured_copy.db_path, protected.db_path);
    assert_eq!(configured_copy.http_bind, protected.http_bind);
    assert_eq!(
        configured_copy.replay_integrity_key_path,
        protected.replay_integrity_key_path
    );
    assert_eq!(configured_copy.max_in_flight, protected.max_in_flight);
    assert_eq!(
        configured_copy.shutdown_timeout_ms,
        protected.shutdown_timeout_ms
    );
    assert_eq!(
        configured_copy.provider_activation.binding(),
        protected.provider_activation.binding()
    );
    assert_eq!(
        configured_copy.provider_activation_settings.accounting_mode,
        protected.provider_activation_settings.accounting_mode
    );
    assert_eq!(
        configured_copy.d2_safe_tool_loop_budget.unwrap().limits(),
        Some((12000, 400000))
    );
}
