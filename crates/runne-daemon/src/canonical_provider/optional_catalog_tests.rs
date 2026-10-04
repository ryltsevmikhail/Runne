use super::*;
use crate::config::{BuiltInDefaults, ConfigurationSnapshot, SystemConfig};

fn input_text() -> String {
    let profile = OpenAiResponsesTextProfile::from_json(SOURCE).unwrap();
    format!(
        "schema_version=2\n[secondary_profile_catalog]\nprovider_id='{}'\nprofile_id='{}'\ncredential_realm='{}'\nprofile_digest='{}'\npricing_revision_digest='{}'\ntoken_budget_limit=1000\ncost_budget_limit_micros=50000\n",
        profile.provider_id(),
        profile.profile_id(),
        profile.provider_id(),
        hex::encode(profile.profile_digest()),
        hex::encode(profile.pricing_revision_digest())
    )
}

fn verified_snapshot(text: &str, path: &std::path::Path) -> VerifiedFixedExternalConfig {
    let system: SystemConfig = toml::from_str(text).unwrap();
    let defaults = BuiltInDefaults::new(path);
    let snapshot =
        ConfigurationSnapshot::from_merge(&defaults, &system, &external_config_path()).unwrap();
    VerifiedFixedExternalConfig::from_test_snapshot(snapshot)
}

#[test]
fn fixed_owner_config_compiles_exact_tuple_and_binds_db_authority() {
    let dir = tempfile::tempdir().unwrap();
    let verified = verified_snapshot(&input_text(), dir.path());
    let catalog = VerifiedSecondaryCatalog::from_fixed_source(
        &verified,
        [5; 16],
        Some(verified.snapshot().db_path.as_str()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(catalog.spec().provider_id(), "openai-background");
    assert_eq!(catalog.spec().credential_realm(), "openai-background");
    assert_eq!(catalog.spec().token_budget_limit(), 1_000);
    assert_eq!(catalog.spec().cost_budget_limit_micros(), 50_000);
    assert_ne!(catalog.digest(), [0; 32]);
    assert!(
        VerifiedSecondaryCatalog::from_fixed_source(
            &verified,
            [5; 16],
            Some("/different/database")
        )
        .is_err()
    );
    let other_owner = VerifiedSecondaryCatalog::from_fixed_source(
        &verified,
        [6; 16],
        Some(verified.snapshot().db_path.as_str()),
    )
    .unwrap()
    .unwrap();
    assert_ne!(catalog.digest(), other_owner.digest());
}

#[test]
fn profile_pricing_and_credential_realm_substitution_fail_closed() {
    let source = input_text();
    let profile = OpenAiResponsesTextProfile::from_json(SOURCE).unwrap();
    for invalid in [
        source.replace("provider_id='openai-background'", "provider_id='openai'"),
        source.replace(
            "profile_id='gocode-openai-responses-background-text/1'",
            "profile_id='other/1'",
        ),
        source.replace(
            "credential_realm='openai-background'",
            "credential_realm='openai'",
        ),
        source.replace(
            &format!("profile_digest='{}'", hex::encode(profile.profile_digest())),
            &format!("profile_digest='{}'", hex::encode([7; 32])),
        ),
        source.replace(
            &format!(
                "pricing_revision_digest='{}'",
                hex::encode(profile.pricing_revision_digest())
            ),
            &format!("pricing_revision_digest='{}'", hex::encode([8; 32])),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let verified = verified_snapshot(&invalid, dir.path());
        assert!(VerifiedSecondaryCatalog::from_fixed_source(&verified, [5; 16], None).is_err());
    }
}

#[test]
fn absent_catalog_stays_absent_and_zero_or_missing_budgets_are_denied() {
    let dir = tempfile::tempdir().unwrap();
    let defaults = BuiltInDefaults::new(dir.path());
    let no_catalog: SystemConfig = toml::from_str("schema_version=2").unwrap();
    let snapshot =
        ConfigurationSnapshot::from_merge(&defaults, &no_catalog, &external_config_path()).unwrap();
    let verified = VerifiedFixedExternalConfig::from_test_snapshot(snapshot);
    assert!(
        VerifiedSecondaryCatalog::from_fixed_source(&verified, [5; 16], None)
            .unwrap()
            .is_none()
    );

    let zero = input_text().replace("token_budget_limit=1000", "token_budget_limit=0");
    let zero = verified_snapshot(&zero, dir.path());
    assert!(VerifiedSecondaryCatalog::from_fixed_source(&zero, [5; 16], None).is_err());
    let zero_cost = input_text().replace(
        "cost_budget_limit_micros=50000",
        "cost_budget_limit_micros=0",
    );
    let zero_cost = verified_snapshot(&zero_cost, dir.path());
    assert!(VerifiedSecondaryCatalog::from_fixed_source(&zero_cost, [5; 16], None).is_err());
    let missing = input_text().replace("cost_budget_limit_micros=50000\n", "");
    assert!(toml::from_str::<SystemConfig>(&missing).is_err());
    let missing_tokens = input_text().replace("token_budget_limit=1000\n", "");
    assert!(toml::from_str::<SystemConfig>(&missing_tokens).is_err());
}
