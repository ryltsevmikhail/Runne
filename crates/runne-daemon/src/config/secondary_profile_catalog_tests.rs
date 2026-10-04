use super::*;

fn catalog_toml() -> String {
    let profile = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/openai-responses-background-text-v1.json"
    ))
    .unwrap();
    format!(
        "schema_version=2\n[secondary_profile_catalog]\nprovider_id='{}'\nprofile_id='{}'\ncredential_realm='{}'\nprofile_digest='{}'\npricing_revision_digest='{}'\ntoken_budget_limit=1000\ncost_budget_limit_micros=50000\n",
        profile.provider_id(),
        profile.profile_id(),
        profile.provider_id(),
        hex::encode(profile.profile_digest()),
        hex::encode(profile.pricing_revision_digest())
    )
}

#[test]
fn optional_catalog_does_not_change_primary_configuration_digest() {
    let dir = tempfile::tempdir().unwrap();
    let defaults = BuiltInDefaults::new(dir.path());
    let base: SystemConfig = toml::from_str("schema_version=2").unwrap();
    let with_catalog: SystemConfig = toml::from_str(&catalog_toml()).unwrap();
    let path = external_config_path();
    let primary = ConfigurationSnapshot::from_merge(&defaults, &base, &path).unwrap();
    let optional = ConfigurationSnapshot::from_merge(&defaults, &with_catalog, &path).unwrap();
    assert_eq!(primary.digest, optional.digest);
    assert!(primary.secondary_profile_catalog.is_none());
    assert!(optional.secondary_profile_catalog.is_some());
    assert_eq!(
        optional.provenance["secondary_profile_catalog"].source,
        Source::SystemFile
    );
}

#[test]
fn optional_catalog_rejects_unknown_and_missing_budget_fields() {
    let missing_budget = catalog_toml().replace("cost_budget_limit_micros=50000\n", "");
    assert!(toml::from_str::<SystemConfig>(&missing_budget).is_err());
    let unknown = catalog_toml().replace(
        "cost_budget_limit_micros=50000",
        "cost_budget_limit_micros=50000\nautomatic_fallback=true",
    );
    assert!(toml::from_str::<SystemConfig>(&unknown).is_err());
}
