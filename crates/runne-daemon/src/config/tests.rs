use super::*;
use crate::provider_activation::ProviderAccountingMode;
use std::fs;

fn private_config(path: &std::path::Path, contents: &str) {
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn external_native_accounting_roundtrips_into_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let digest = hex::encode(runne_api::NATIVE_MINIMAX_PROFILE_DIGEST);
    private_config(
        &path,
        &format!(
            "schema_version = 2\n\n[provider_activation]\nmode = \"native_text_v1\"\nprofile_id = \"{}\"\nprofile_digest = \"{}\"\n\n[provider_activation.settings]\naccounting_mode = \"payg\"\n",
            runne_api::NATIVE_MINIMAX_PROFILE_ID,
            digest
        ),
    );
    let snapshot = load_config(Some(&path)).unwrap();
    assert_eq!(
        snapshot.provider_activation.binding().profile_id(),
        runne_api::NATIVE_MINIMAX_PROFILE_ID
    );
    assert_eq!(
        snapshot.provider_activation_settings.accounting_mode,
        Some(ProviderAccountingMode::Payg)
    );
    assert!(!snapshot.digest.is_empty());
}

#[test]
fn external_settings_for_another_provider_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    private_config(
        &path,
        &format!(
            "schema_version = 2\n\n[provider_activation]\nmode = \"native_text_v1\"\nprofile_id = \"{}\"\nprofile_digest = \"{}\"\n\n[provider_activation.settings]\naccounting_mode = \"subscription\"\n",
            runne_api::NATIVE_ANTHROPIC_PROFILE_ID,
            hex::encode(runne_api::NATIVE_ANTHROPIC_PROFILE_DIGEST)
        ),
    );
    assert!(matches!(
        load_config(Some(&path)),
        Err(DaemonError::Config(_))
    ));
}

#[test]
fn external_responses_payg_config_recomputes_derived_profile_digest() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let pricing = hex::encode(runne_provider_responses_wire::derive_payg_pricing_digest(
        runne_provider_responses_wire::ResponsesProvider::Xai,
        runne_provider_responses_wire::XAI_MODEL,
        2_000_000,
        10_000_000,
        200_000,
    ));
    private_config(
        &path,
        &format!(
            "schema_version = 2\n\n[provider_activation]\nmode = \"responses_text_v1\"\nprofile_id = \"gocode-responses/xai/grok-4.3/1\"\nprofile_digest = \"derived\"\n\n[provider_activation.settings]\nresponses_pricing_digest = \"{pricing}\"\nresponses_input_micros_per_million = 2000000\nresponses_output_micros_per_million = 10000000\nresponses_cached_input_micros_per_million = 200000\naccounting_mode = \"payg\"\n"
        ),
    );
    let snapshot = load_config(Some(&path)).unwrap();
    assert_eq!(
        snapshot.provider_activation.binding().profile_id(),
        "gocode-responses/xai/grok-4.3/1"
    );
    assert_eq!(
        snapshot
            .provider_activation_settings
            .responses_output_micros_per_million,
        Some(10_000_000)
    );
}

#[test]
fn external_radius_config_recomputes_derived_profile_digest() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    private_config(
        &path,
        r#"schema_version = 2

[provider_activation]
mode = "radius_text_v1"
profile_id = "gocode-radius-text/dynamic/1"
profile_digest = "derived"

[provider_activation.settings]
radius_catalog_json = '{"baseUrl":"https://radius.pi.dev","models":[{"id":"fixture-model","name":"Fixture","reasoning":false,"input":["text"],"contextWindow":8192,"maxTokens":1024,"cost":{"input":1,"output":2,"cacheRead":0.1,"cacheWrite":0}}]}'
radius_model_id = "fixture-model"
radius_revision = "fixture-rev"
"#,
    );
    let snapshot = load_config(Some(&path)).unwrap();
    let catalog = runne_provider_radius::RadiusCatalog::from_json_at(
        snapshot
            .provider_activation_settings
            .radius_catalog
            .as_deref()
            .unwrap(),
        runne_provider_radius::DEFAULT_RADIUS_GATEWAY,
    )
    .unwrap();
    let expected = catalog
        .select("radius", "fixture-model", "fixture-rev")
        .unwrap()
        .profile_digest();
    assert_eq!(
        snapshot.provider_activation.binding().profile_digest(),
        &expected
    );
}
