use super::{ResponsesProfile, ResponsesProvider};
use runne_provider::TextProviderProfile;

#[test]
fn uses_codex_responses_route_and_exact_profile_id() {
    let profile = ResponsesProfile::new(ResponsesProvider::OpenAiCodex, "gpt-5.2");
    assert_eq!(
        profile.profile_id(),
        "gocode-responses/openai-codex/gpt-5.2/1"
    );
    assert_eq!(
        profile.endpoint(),
        "https://chatgpt.com/backend-api/codex/responses"
    );
}

#[test]
fn azure_uses_v1_route_and_sends_deployment_as_model() {
    let profile = ResponsesProfile::azure("tenant", "deployment-prod", "gpt-5.2").unwrap();
    assert_eq!(
        profile.endpoint(),
        "https://tenant.openai.azure.com/openai/v1/responses"
    );
    assert_eq!(profile.model(), "gpt-5.2");
    assert_eq!(profile.request_model(), "deployment-prod");
}

#[test]
fn azure_components_are_strictly_validated() {
    assert!(ResponsesProfile::azure("tenant.example", "deployment", "gpt").is_err());
    assert!(ResponsesProfile::azure("tenant", "../deployment", "gpt").is_err());
}

#[test]
fn default_call_extension_is_standard_and_not_self_referential() {
    let profile = ResponsesProfile::new(ResponsesProvider::Xai, "grok-4")
        .with_model_revision("pi/revision")
        .with_pricing_revision_digest([7; 32]);
    let extension = profile.call_binding_extension();
    assert_eq!(extension["profile_id"], profile.profile_id());
    assert_eq!(
        extension["profile_digest"],
        hex::encode(profile.profile_digest())
    );
    assert_eq!(
        extension["pricing_revision_digest"],
        hex::encode(profile.pricing_revision_digest())
    );
    assert_eq!(profile.binding_extension(), &serde_json::Value::Null);
}

#[test]
fn aliases_are_bounded_and_profile_digest_framing_is_unambiguous() {
    let profile = ResponsesProfile::new(ResponsesProvider::Xai, "grok-4")
        .with_model_revision("pi/revision")
        .with_pricing_revision_digest([8; 32]);
    let mut nul_alias = profile.clone();
    nul_alias.aliases.push("a\0b".to_owned());
    let split_aliases = profile
        .clone()
        .with_alias("a")
        .unwrap()
        .with_alias("b")
        .unwrap();
    assert_ne!(nul_alias.profile_digest(), split_aliases.profile_digest());
    assert!(nul_alias.validate().is_err());
    assert!(split_aliases.validate().is_ok());
    assert!(profile.clone().with_alias("a\0b").is_err());
    assert!(profile.clone().with_alias("x".repeat(513)).is_err());
    let mut too_many = profile;
    for _ in 0..16 {
        too_many = too_many.with_alias("x").unwrap();
    }
    assert!(too_many.with_alias("y").is_err());
}
