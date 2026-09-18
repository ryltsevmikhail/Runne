use super::*;
use crate::provider_activation::ProviderActivationSettings;
use runne_api::{ProviderActivationBindingV1, ProviderActivationModeV1};
use runne_provider::TextProviderProfile;
use runne_provider_radius::RadiusCatalog;
use sha2::{Digest, Sha256};

const RADIUS_CATALOG: &[u8] = br#"{"baseUrl":"https://radius.pi.dev","models":[{"id":"fixture-model","name":"Fixture","reasoning":false,"input":["text"],"cost":{"input":1,"output":2,"cacheRead":0.1,"cacheWrite":0},"contextWindow":8192,"maxTokens":1024}]}"#;

fn native_activation(profile_id: &str, digest: [u8; 32]) -> ProviderActivation {
    ProviderActivation::from_binding(
        ProviderActivationBindingV1::new(
            ProviderActivationModeV1::NativeTextV1,
            profile_id,
            digest,
        )
        .unwrap(),
    )
}

fn vertex_digest(project: &str, location: &str) -> [u8; 32] {
    Sha256::digest(format!(
        "runne/native-profile/v2|google-vertex|gocode-native/google-vertex/gemini-2.5-flash/1|gemini-2.5-flash|pi-0.85.1|https://{location}-aiplatform.googleapis.com|project:{project}|location:{location}|vertex_bearer|1048576|64:262144:1966080:983040:65536:8388608:65536|payg:300000:2500000:30000:0"
    ).as_bytes()).into()
}

#[test]
fn generic_runtime_lookup_rejects_unknown_and_tampered_profiles() {
    let unknown = ProviderActivationBindingV1::new(
        ProviderActivationModeV1::GenericChatCompletionsTextV1,
        "gocode-chat-completions/unknown/1",
        [7; 32],
    )
    .unwrap();
    assert!(generic_profile(&unknown).is_none());

    let known = runne_provider_chat_completions::generic_profiles()
        .first()
        .unwrap();
    let tampered = ProviderActivationBindingV1::new(
        ProviderActivationModeV1::GenericChatCompletionsTextV1,
        known.profile_id,
        [7; 32],
    )
    .unwrap();
    assert!(generic_profile(&tampered).is_none());
}

#[test]
fn all_native_profiles_select_exactly_and_vertex_binds_route_inputs() {
    let profiles = [
        (
            runne_api::NATIVE_ANTHROPIC_PROFILE_ID,
            runne_api::NATIVE_ANTHROPIC_PROFILE_DIGEST,
        ),
        (
            runne_api::NATIVE_GOOGLE_PROFILE_ID,
            runne_api::NATIVE_GOOGLE_PROFILE_DIGEST,
        ),
        (
            runne_api::NATIVE_KIMI_PROFILE_ID,
            runne_api::NATIVE_KIMI_PROFILE_DIGEST,
        ),
        (
            runne_api::NATIVE_MINIMAX_PROFILE_ID,
            runne_api::NATIVE_MINIMAX_PROFILE_DIGEST,
        ),
        (
            runne_api::NATIVE_MINIMAX_CN_PROFILE_ID,
            runne_api::NATIVE_MINIMAX_CN_PROFILE_DIGEST,
        ),
        (
            runne_api::NATIVE_VERCEL_PROFILE_ID,
            runne_api::NATIVE_VERCEL_PROFILE_DIGEST,
        ),
    ];
    for (profile_id, digest) in profiles {
        let activation = native_activation(profile_id, digest);
        let activation = if profile_id.contains("minimax") {
            ProviderActivation::from_binding_with_settings(
                activation.binding().clone(),
                ProviderActivationSettings {
                    accounting_mode: Some(crate::provider_activation::ProviderAccountingMode::Payg),
                    ..Default::default()
                },
            )
        } else {
            activation
        };
        let selected = select_provider_runtime(&activation).unwrap().unwrap();
        assert_eq!(selected.profile.profile_id(), profile_id);
        assert_eq!(
            selected.profile.profile_digest(),
            *activation.binding().profile_digest()
        );
        assert_eq!(
            selected.profile.currency(),
            if profile_id.contains("kimi") {
                "XXX"
            } else {
                "USD"
            }
        );
    }

    let project = "runne-fixture";
    let location = "us-central1";
    let binding = ProviderActivationBindingV1::new(
        ProviderActivationModeV1::NativeTextV1,
        runne_api::NATIVE_VERTEX_PROFILE_ID,
        vertex_digest(project, location),
    )
    .unwrap();
    let activation = ProviderActivation::from_binding_with_settings(
        binding,
        ProviderActivationSettings {
            vertex_project: Some(project.to_owned()),
            vertex_location: Some(location.to_owned()),
            ..Default::default()
        },
    );
    let selected = select_provider_runtime(&activation).unwrap().unwrap();
    assert_eq!(
        selected.profile.profile_id(),
        runne_api::NATIVE_VERTEX_PROFILE_ID
    );

    let mismatched = ProviderActivation::from_binding_with_settings(
        activation.binding().clone(),
        ProviderActivationSettings {
            vertex_project: Some(project.to_owned()),
            vertex_location: Some("europe-west1".to_owned()),
            ..Default::default()
        },
    );
    assert!(select_provider_runtime(&mismatched).is_err());

    let mismatched_project = ProviderActivation::from_binding_with_settings(
        activation.binding().clone(),
        ProviderActivationSettings {
            vertex_project: Some("other-project".to_owned()),
            vertex_location: Some(location.to_owned()),
            ..Default::default()
        },
    );
    assert!(select_provider_runtime(&mismatched_project).is_err());
}

#[test]
fn minimax_and_minimax_cn_bind_payg_and_token_plan_separately() {
    for (profile_id, provider, endpoint) in [
        (
            runne_api::NATIVE_MINIMAX_PROFILE_ID,
            "minimax",
            "https://api.minimax.io/anthropic",
        ),
        (
            runne_api::NATIVE_MINIMAX_CN_PROFILE_ID,
            "minimax-cn",
            "https://api.minimaxi.com/anthropic",
        ),
    ] {
        let digest = Sha256::digest(format!(
            "runne/native-profile/v2|{provider}|{profile_id}|MiniMax-M2.7|pi-0.85.1|{endpoint}|anthropic_api_key|204800|64:262144:147456:73728:131072:8388608:65536|token_plan"
        ).as_bytes()).into();
        let activation = ProviderActivation::from_binding_with_settings(
            ProviderActivationBindingV1::new(
                ProviderActivationModeV1::NativeTextV1,
                profile_id,
                digest,
            )
            .unwrap(),
            ProviderActivationSettings {
                accounting_mode: Some(
                    crate::provider_activation::ProviderAccountingMode::TokenPlan,
                ),
                ..Default::default()
            },
        );
        let selected = select_provider_runtime(&activation).unwrap().unwrap();
        assert_eq!(selected.profile.currency(), "XXX");
        assert_eq!(selected.profile.profile_digest(), digest);
    }
}

#[test]
fn radius_selection_requires_fixture_catalog_and_exact_digest() {
    let catalog = RadiusCatalog::from_json_at(RADIUS_CATALOG, "https://radius.pi.dev").unwrap();
    let profile = catalog
        .select("radius", "fixture-model", "fixture-rev")
        .unwrap();
    let binding = ProviderActivationBindingV1::new(
        ProviderActivationModeV1::RadiusTextV1,
        runne_api::RADIUS_TEXT_PROFILE_ID,
        profile.profile_digest(),
    )
    .unwrap();
    let activation = ProviderActivation::from_binding_with_settings(
        binding,
        ProviderActivationSettings {
            radius_catalog: Some(RADIUS_CATALOG.to_vec()),
            radius_model_id: Some("fixture-model".to_owned()),
            radius_revision: Some("fixture-rev".to_owned()),
            ..Default::default()
        },
    );
    let selected = select_provider_runtime(&activation).unwrap().unwrap();
    assert_eq!(
        selected.profile.profile_id(),
        runne_api::RADIUS_TEXT_PROFILE_ID
    );
    assert_eq!(selected.profile.currency(), "XXX");

    let tampered = ProviderActivationBindingV1::new(
        ProviderActivationModeV1::RadiusTextV1,
        runne_api::RADIUS_TEXT_PROFILE_ID,
        [9; 32],
    )
    .unwrap();
    let bad = ProviderActivation::from_binding_with_settings(
        tampered,
        activation.settings().unwrap().clone(),
    );
    assert!(select_provider_runtime(&bad).is_err());
}
